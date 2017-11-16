package sodiumbox

import (
	"crypto/rand"
	"io"

	"github.com/pkg/errors"

	"golang.org/x/crypto/blake2b"
	naclbox "golang.org/x/crypto/nacl/box"
)

// NonceSize is the number of bytes in a nonce
const NonceSize = 24

// KeySize is the number of bytes in a key
const KeySize = 32

// Overhead is `len(boxedMsg) - len(originalMessage)`
const Overhead = naclbox.Overhead + KeySize

// Seal encrypts a message such that it can be read with the peer's keypair
func Seal(msg []byte, peerPubkey *[KeySize]byte) (box []byte, err error) {
	ephemeralPubkey, ephemeralPrivkey, err := naclbox.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "sodiumbox: unable to generate keys")
	}

	nonce, err := genNonce(ephemeralPubkey, peerPubkey)
	if err != nil {
		return nil, errors.Wrap(err, "sodiumbox: unable to generate nonce")
	}

	overhead := naclbox.Overhead + len(ephemeralPubkey)
	box = make([]byte, 0, overhead+len(msg))
	box = append(box, ephemeralPubkey[:]...)
	box = naclbox.Seal(box, msg, nonce, peerPubkey, ephemeralPrivkey)
	return
}

// Open authenticates and decrypts a box such that it can be read
func Open(box []byte, pubKey, privKey *[KeySize]byte) (msg []byte, err error) {
	if len(box) < KeySize {
		return nil, errors.New("sodiumbox: box contains less data than a pubkey")
	}

	var peerPubkey [KeySize]byte
	copy(peerPubkey[:], box[:KeySize])
	boxedMsg := box[KeySize:]

	nonce, err := genNonce(&peerPubkey, pubKey)

	msg, ok := naclbox.Open(nil, boxedMsg, nonce, &peerPubkey, privKey)
	if !ok {
		return nil, errors.New("sodiumbox: unable to open box")
	}
	return
}

// GenerateKey creates a new keypair. It simply wraps the
// underlying NaCl generator.
func GenerateKey(rand io.Reader) (pubKey, privKey *[KeySize]byte, err error) {
	return naclbox.GenerateKey(rand)
}

// genNonce creates a nonce from the two pubkeys in this transaction.
// This result must not be used more than once with the same pair of
// public keys.
func genNonce(ephemeralPubkey, pubKey *[KeySize]byte) (*[NonceSize]byte, error) {
	nonce := &[NonceSize]byte{}

	nonceHasher, err := blake2b.NewDigest(NonceSize, nil)
	nonceHasher.Reset()
	if err != nil {
		return nil, err
	}

	_, err = nonceHasher.Write(ephemeralPubkey[:])
	if err != nil {
		return nil, err
	}

	_, err = nonceHasher.Write(pubKey[:])
	if err != nil {
		return nil, err
	}

	nonceSlice := nonceHasher.Sum(nil)
	copy(nonce[:], nonceSlice)

	return nonce, nil
}
