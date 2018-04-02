package tunnel

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bgentry/speakeasy"
	"github.com/kr/pty"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/terminal"
)

// RsshParameters is the given params for the SSH connection
type RsshParameters struct {
	Address        string
	Command        string
	IdentityFile   string
	IgnoreHostKeys bool
	ListenAddress  string
	Username       string
	Timeout        string
	Retry          int
}

// DoRssh starts the Rssh connection with the given options
func DoRssh(params RsshParameters) error {
	log.Debugf("Configuring SSH connection with params %+v", params)

	config := &ssh.ClientConfig{
		User: params.Username,
		Auth: nil,
	}

	if params.Timeout == "" {
		params.Timeout = "30s"
	}

	if timeout, err := time.ParseDuration(params.Timeout); err == nil {
		log.Infof("Setting SSH connection timeout to: %s", params.Timeout)
		config.Timeout = timeout
	} else {
		return errors.Wrap(err, "failed to set timeout")
	}

	if !strings.Contains(params.Address, ":") {
		params.Address += ":22"
	}
	log.Infof("Initializing reverse ssh connection to %s", params.Address)

	if ids, err := locateIdentiyFile(params.IdentityFile); err == nil {
		for _, id := range ids {
			if _, err := os.Stat(id); err == nil {
				auth, err := loadPrivateKey(id)
				if err != nil {
					log.Warnf("Unable to load identity file '%s': %s", id, err)
				} else {
					log.Infof("Adding identity file '%s' to ssh auth list", id)
					config.Auth = append(config.Auth, auth)
				}
			}
		}
	}

	if agentConn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err != nil {
		log.Infof("Adding ssh agent to auth list")
		config.Auth = append(config.Auth, ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers))
	}

	if params.IgnoreHostKeys {
		log.Warn("Ignoring host key checking.  This is insecure!")
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// Connect to the remote host over SSH
	sshConn, err := ssh.Dial("tcp", params.Address, config)
	if err != nil {
		return errors.Wrap(err, "unable to dial remote host")
	}
	defer sshConn.Close()

	// Start listening on the remote address
	l, err := sshConn.Listen("tcp", params.ListenAddress)
	if err != nil {
		return errors.Wrap(err, "unable to listen on remote host")
	}

	// Start accepting shell connections
	log.Infof("Listening for connections on %s (remote listen address: %s)", params.Address, params.ListenAddress)
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Errorf("error accepting connection: %s", err)
			continue
		}

		log.Infof("accepted connection from: %s", conn.RemoteAddr())
		go handleConnection(conn, params.Command)
	}

	return nil
}

func locateIdentiyFile(paramFile string) ([]string, error) {
	log.Debugf("Locating identity file, location param: '%s'", paramFile)

	// If we got an identity file as a param, just use it
	if paramFile != "" {
		if _, err := os.Stat(paramFile); err != nil {
			return []string{}, fmt.Errorf("%s not found", paramFile)
		}
		return []string{paramFile}, nil
	}

	home, err := homedir.Dir()
	if err != nil {
		return []string{}, err
	}

	var keys []string
	tunnelrPath := filepath.Join(home, ".tunnelr")
	if _, err := os.Stat(tunnelrPath); err == nil {
		fs := afero.Afero{Fs: afero.NewBasePathFs(afero.NewOsFs(), tunnelrPath)}
		fs.Walk("/", func(path string, info os.FileInfo, err error) error {
			log.Debugf("Processing potential key at %s", path)
			if err != nil {
				log.Errorf("Returning error from walk: %s", err.Error())
				return err
			}

			if !info.IsDir() {
				// Read file
				keyData, err := ioutil.ReadFile(path)
				if err != nil {
					msg := fmt.Sprintf("could not read key file '%s'", path)
					return errors.Wrap(err, msg)
				}

				// Get first PEM block
				block, _ := pem.Decode(keyData)
				if block == nil {
					return fmt.Errorf("no key found in file '%s'", path)
				}

				keys = append(keys, path)
			}

			return nil
		})
	}

	// try using tunnelr generated keys
	tunnelrKeys := filepath.Join(home, ".tunnelr/id_rsa")
	if _, err := os.Stat(tunnelrKeys); err == nil {
		keys = append(keys, tunnelrKeys)
	}

	// try using default ssh keys
	sshKeys := filepath.Join(home, ".ssh/id_rsa")
	if _, err := os.Stat(sshKeys); err == nil {
		keys = append(keys, sshKeys)
	}

	return keys, nil
}

// https://github.com/andrew-d/rssh/blob/master/main.go#L258
func loadPrivateKey(path string) (ssh.AuthMethod, error) {
	// Read file
	keyData, err := ioutil.ReadFile(path)
	if err != nil {
		msg := fmt.Sprintf("could not read key file '%s'", path)
		return nil, errors.Wrap(err, msg)
	}

	// Get first PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("no key found in file '%s'", path)
	}

	// If it's encrypted...
	var (
		signer    ssh.Signer
		signerErr error
	)

	if x509.IsEncryptedPEMBlock(block) {
		// Get the passphrase
		prompt := fmt.Sprintf("Enter passphrase for key '%s': ", path)
		pass, err := speakeasy.Ask(prompt)
		if err != nil {
			return nil, errors.Wrap(err, "failed getting passphrase")
		}

		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(pass))
		if err != nil {
			return nil, errors.Wrap(err, "failed decrypting key")
		}

		key, err := ParsePEMBlock(block)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse PEM block")
		}

		signer, signerErr = ssh.NewSignerFromKey(key)
	} else {
		signer, signerErr = ssh.ParsePrivateKey(keyData)
	}

	if signerErr != nil {
		msg := fmt.Sprintf("failed parsing private key '%s': %s", path, signerErr)
		return nil, errors.Wrap(err, msg)
	}

	return ssh.PublicKeys(signer), nil
}

// See: https://github.com/golang/crypto/blob/master/ssh/keys.go#L598
func ParsePEMBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "DSA PRIVATE KEY":
		return ssh.ParseDSAPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

func handleConnection(c net.Conn, command string) {
	defer c.Close()

	// Start the command
	cmd := exec.Command("/bin/sh")

	// Create PTY
	pty, tty, err := pty.Open()
	if err != nil {
		log.Errorf("could not open PTY: %s", err)
		return
	}
	defer tty.Close()
	defer pty.Close()

	// Put the TTY into raw mode
	_, err = terminal.MakeRaw(int(tty.Fd()))
	if err != nil {
		log.Warnf("warn: could not make TTY raw: %s", err)
	}

	// Hook everything up
	cmd.Stdout = tty
	cmd.Stdin = tty
	cmd.Stderr = tty
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Setsid = true

	// Start command
	err = cmd.Start()
	if err != nil {
		log.Errorf("error: could not start command: %s", err)
		return
	}

	errs := make(chan error, 3)

	go func() {
		_, err := io.Copy(c, pty)
		errs <- err
	}()
	go func() {
		_, err := io.Copy(pty, c)
		errs <- err
	}()
	go func() {
		errs <- cmd.Wait()
	}()

	// Wait for a single error, then shut everything down. Since returning from
	// this function closes the connection, we just read a single error and
	// then continue.
	<-errs
	log.Infof("connection from %s finished", c.RemoteAddr())
}
