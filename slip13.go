package slip13

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/lmars/go-slip10"
)

// Purpose is the BIP43 purpose field used by SLIP-0013
const Purpose uint32 = 13

// Derive derives a HD node from the given master key, uri and index using the
// SLIP-0013 algorithm.
//
// See https://github.com/satoshilabs/slips/blob/master/slip-0013.md
func Derive(key *slip10.Key, uri string, index uint32) (*slip10.Key, error) {
	return DeriveWithPurpose(key, Purpose, uri, index)
}

// DeriveWithPurpose is the same as Derive but supports using a custom purpose
// (rather than the spec defined value of 13).
func DeriveWithPurpose(key *slip10.Key, purpose uint32, uri string, index uint32) (*slip10.Key, error) {
	// 1. First concatenate index with the URI (uri). Use little endian for index.
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, index)
	data := append(buf, []byte(uri)...)

	// 2. Compute the SHA256 hash of the result (hash).
	sha := sha256.Sum256(data)

	// 3. Truncate hash to 128 bits (hash128)
	hash := sha[:16]

	// 4. Split hash128 into four 32-bit integers A, B, C, D. Use little endian for each.
	a := binary.LittleEndian.Uint32(hash[0:4])
	b := binary.LittleEndian.Uint32(hash[4:8])
	c := binary.LittleEndian.Uint32(hash[8:12])
	d := binary.LittleEndian.Uint32(hash[12:16])

	// 5. Set highest bits of numbers A, B, C, D to 1 (e.g. logical OR with 0x80000000) to harden
	purpose |= 0x80000000
	a |= 0x80000000
	b |= 0x80000000
	c |= 0x80000000
	d |= 0x80000000

	// 6. Derive the HD node m/13'/A'/B'/C'/D' according to BIP32.
	for _, index := range []uint32{purpose, a, b, c, d} {
		var err error
		key, err = key.NewChildKey(index)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}
