# MahJson SDK for Go language

## Installing

To start using mahjson, install Go and run `go get`:

```sh
$ go get -u github.com/pnp200/mahjson
```

This will retrieve the library.


## Example
```go
package main

import (
  "fmt"
  "time"
  "github.com/pnp200/mahjson"
  "github.com/tidwall/gjson"
)

func main() {
	url := "your test url"
	publicKey := "your assigned public key"
	privateKey := "your private key"

	net, err := mahjson.NewClient(url, publicKey, privateKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	// Network Check
	netCheck, err := net.NetworkCheck()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(netCheck)
}
```

## Documentation
[Documentation](https://sandbox.ghlapps.com/apidoc/)
