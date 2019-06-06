# go-slip13

An implementation of the [SLIP-0013 spec](https://github.com/satoshilabs/slips/blob/master/slip-0013.md) for Authentication using deterministic hierarchy as a simple Go library.

## Usage

This library is best used in conjunction with [go-slip10](https://github.com/lmars/go-slip10):

```go
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	slip10 "github.com/lmars/go-slip10"
	slip13 "github.com/lmars/go-slip13"
)

func main() {
	// generate a random seed (you could equally use go-bip39 to derive
	// a seed from a mnemonic)
	seed, err := slip10.NewSeed()
	if err != nil {
		log.Fatal(err)
	}

	// derive the master key
	masterKey, err := slip10.NewMasterKey(seed)
	if err != nil {
		log.Fatal(err)
	}

	// use go-slip13 to derive a SLIP-0013 authentication key for uri
	// "https://alice@example.com" and index 21
	authKey, err := slip13.Derive(masterKey, "https://alice@example.com", 21)
	if err != nil {
		log.Fatal(err)
	}

	// print the public key
	fmt.Println("Public key:", hex.EncodeToString(authKey.PublicKey().Key))
}
```
