# tunnelr

The plan is for this to be a one-stop-shop for creating a reverse tunnel.

It should eventually:

* Setup keys (on both sides)
* Setup reverse ssh tunnel
* [maybe] offer a non-ssh client listener (that basically will just implement an ssh server)

It will create the `~/.tunnelr` directory and drop stuff there by default.  The formats of things in that dir may change.

## Usage

```bash
A tunnel digger

Usage:
  tunnelr [command]

Available Commands:
  help        Help about any command
  keys        Generates key pair for use with tunnelr
  rssh        Opens reverse ssh connection to an address

Flags:
  -h, --help     help for tunnelr
  -t, --toggle   Help message for toggle

Use "tunnelr [command] --help" for more information about a command.
```

### keys

Generate some ssh keys

```bash
Generates key pair for use with tunnelr

Usage:
  tunnelr keys [flags]

Flags:
  -h, --help          help for keys
  -n, --name string   name for the generated keys (without extension) (default "id_rsa")
```

### rssh

Heavily influenced by [andrew-d's rssh](https://github.com/andrew-d/rssh).  Probably made worse by wrapping things
the way I generally do them in Go[lang].  Integrated into tunnelr as a subcommand.

```bash
Opens reverse ssh connection to an address

Usage:
  tunnelr rssh [flags]

Flags:
  -c, --command string    local command to execute (default "/bin/sh")
  -h, --help              help for rssh
  -i, --identity string   ssh identity (key) file
      --insecure          ignore host key verification
  -l, --listen string     remote listen address and port (default "127.0.0.1:22345")
  -u, --username string   connect as given username
```

## License

```
The MIT License (MIT)

Copyright © 2018 E Camden Fisher <fish@fishnix.net>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```