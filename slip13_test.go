package slip13

import (
	"encoding/hex"
	"testing"

	slip10 "github.com/lmars/go-slip10"
	bip39 "github.com/tyler-smith/go-bip39"
)

// TestDerive tests deriving keys using test vectors from
// https://github.com/trezor/trezor-firmware/blob/python/v0.11.3/python/trezorlib/tests/device_tests/test_msg_signidentity.py#L48
func TestDerive(t *testing.T) {
	// derive the master key
	mnemonic := "alcohol woman abuse must during monitor noble actual mixed trade anger aisle"
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		t.Fatal(err)
	}

	// generate the Bitcoin and NIST P-256 master keys
	btcKey, err := slip10.NewMasterKeyWithCurve(seed, slip10.CurveBitcoin)
	if err != nil {
		t.Fatal(err)
	}
	p256Key, err := slip10.NewMasterKeyWithCurve(seed, slip10.CurveP256)
	if err != nil {
		t.Fatal(err)
	}

	// define the test vectors
	type test struct {
		uri         string
		index       uint32
		masterKey   *slip10.Key
		expectedKey string
	}
	tests := []test{
		{
			uri:         "https://satoshi@bitcoin.org/login",
			index:       0,
			masterKey:   btcKey,
			expectedKey: "023a472219ad3327b07c18273717bb3a40b39b743756bf287fbd5fa9d263237f45",
		},
		{
			uri:         "ftp://satoshi@bitcoin.org:2323/pub",
			index:       3,
			masterKey:   btcKey,
			expectedKey: "0266cf12d2ba381c5fd797da0d64f59c07a6f1b034ad276cca6bf2729e92b20d9c",
		},
		{
			uri:         "ssh://satoshi@bitcoin.org",
			index:       47,
			masterKey:   p256Key,
			expectedKey: "0373f21a3da3d0e96fc2189f81dd826658c3d76b2d55bd1da349bc6c3573b13ae4",
		},
	}

	// check the public keys match
	for _, x := range tests {
		key, err := Derive(x.masterKey, x.uri, x.index)
		if err != nil {
			t.Fatal(err)
		}
		actual := hex.EncodeToString(key.PublicKey().Key)
		if actual != x.expectedKey {
			t.Fatalf("wrong public key for %q (%d)\nexpected: %s\nactual:   %s", x.uri, x.index, x.expectedKey, actual)
		}
	}
}
