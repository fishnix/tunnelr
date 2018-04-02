// Copyright © 2018 E Camden Fisher <fish@fishnix.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"os"

	"github.com/fishnix/tunnelr/tunnel"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// Command is the local command to execute on connection
var Command string

// SSHUsername is the username used to connect
var SSHUsername string

// SSHIdentityFile is the identity file (key) for the connection
var SSHIdentityFile string

// SSHIgnoreHostKey is the identity file (key) for the connection
var SSHIgnoreHostKey bool

// SSHIgnoreHostKey is the identity file (key) for the connection
var SSHTimeout string

// ListenAddress is the listen address on the remote host (ie. 127.0.0.1:23456)
var ListenAddress string

// RetryConn is the number of times to retry connecting
var RetryConn int

// rsshCmd represents rssh command
var rsshCmd = &cobra.Command{
	Use:   "rssh",
	Short: "Opens reverse ssh connection to an address",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := tunnel.DoRssh(tunnel.RsshParameters{
			Address:        args[0],
			Username:       SSHUsername,
			IdentityFile:   SSHIdentityFile,
			IgnoreHostKeys: SSHIgnoreHostKey,
			ListenAddress:  ListenAddress,
			Timeout:        SSHTimeout,
			Retry:          RetryConn,
		})

		if err != nil {
			log.Errorf("Failed to connect to %s, %s", args[0], err.Error())
			os.Exit(1)
		}

		os.Exit(0)
	},
}

func init() {
	rsshCmd.Flags().StringVarP(&Command, "command", "c", "/bin/sh", "local command to execute")
	rsshCmd.Flags().StringVarP(&SSHUsername, "username", "u", os.Getenv("USER"), "connect as given username")
	rsshCmd.Flags().StringVarP(&SSHIdentityFile, "identity", "i", "", "ssh identity (key) file")
	rsshCmd.Flags().StringVarP(&ListenAddress, "listen", "l", "127.0.0.1:22345", "remote listen address and port")
	rsshCmd.Flags().BoolVar(&SSHIgnoreHostKey, "insecure", false, "ignore host key verification")
	log.SetLevel(log.DebugLevel)
	rootCmd.AddCommand(rsshCmd)
}
