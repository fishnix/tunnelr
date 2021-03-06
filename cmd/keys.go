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

var KeyName string

// keysCmd represents the normalize command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Generates key pair for use with tunnelr",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Generating key pairs")

		dir, err := tunnel.SetupKeyDir()
		if err != nil || dir == "" {
			log.Errorf("Failed to setup tunnelr dir %s", err)
			os.Exit(10)
		}

		log.Debugf("Setup tunnelr dir %s", dir)

		err = tunnel.GenerateKeys(dir, KeyName)
		if err != nil {
			log.Errorf("Failed to generate tunnelr keys: %s", err)
			os.Exit(20)
		}
		os.Exit(0)
	},
}

func init() {
	keysCmd.Flags().StringVarP(&KeyName, "name", "n", "id_rsa", "name for the generated keys (without extension)")
	rootCmd.AddCommand(keysCmd)
	log.SetLevel(log.DebugLevel)
}
