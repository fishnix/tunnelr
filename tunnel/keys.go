package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// SetupKeyDir creates the directory to store keys
func SetupKeyDir() (string, error) {
	home, err := homedir.Dir()
	if err != nil {
		return "", err
	}

	dir := fmt.Sprintf("%s/.tunnelr", home)

	if f, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.Mkdir(dir, 0700)
		if err != nil {
			return "", err
		}
		return dir, nil
	} else if !f.IsDir() {
		return "", fmt.Errorf("%s exists, but isn't a directory", dir)
	}

	return dir, nil
}

// GenerateKeys generates the rsa key pair
func GenerateKeys(dir, name string) error {
	privateFile := fmt.Sprintf("%s/%s", dir, name)
	publicFile := fmt.Sprintf("%s/%s.pub", dir, name)
	bitSize := 4096

	if _, err := os.Stat(privateFile); err == nil {
		return fmt.Errorf("%s exists, won't overwrite", privateFile)
	}

	if _, err := os.Stat(publicFile); err == nil {
		return fmt.Errorf("%s exists, won't overwrite", publicFile)
	}

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		log.Errorf("Unable to generate %d bit private key", bitSize)
		return err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Errorf("Unable to generate public key")
		return err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, privateFile)
	if err != nil {
		log.Errorf("Unable to write private key to file %s", privateFile)
		return err
	}

	err = writeKeyToFile([]byte(publicKeyBytes), publicFile)
	if err != nil {
		log.Errorf("Unable to write public key to file %s", publicFile)
		return err
	}

	return nil
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key generated")
	return pubKeyBytes, nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	log.Printf("Key saved to: %s", saveFileTo)
	return nil
}
