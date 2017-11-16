//+build cgo

package sodiumbox_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xyziemba/sodiumbox"
	"github.com/xyziemba/sodiumbox/interop"
	naclbox "golang.org/x/crypto/nacl/box"
)

func TestNativeRoundtrip(t *testing.T) {
	pubkey, privkey, err := naclbox.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	for _, test := range roundtripTests {
		t.Run(test.name, func(t *testing.T) {
			msg := []byte(test.content)
			box := interop.NativeBoxSeal(msg, pubkey) //nolint: gotypex

			actMsg, err := interop.NativeBoxOpen(box, pubkey, privkey) //nolint: gotypex
			assert.NoError(t, err)
			assert.Equal(t, msg, actMsg)
		})
	}
}

func TestNativeEncryptGoDecrypt(t *testing.T) {
	pubkey, privkey, err := naclbox.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	for _, test := range roundtripTests {
		t.Run(test.name, func(t *testing.T) {
			msg := []byte(test.content)
			box := interop.NativeBoxSeal(msg, pubkey) //nolint: gotypex

			actMsg, err := sodiumbox.Open(box, pubkey, privkey)
			assert.NoError(t, err)
			assert.Equal(t, msg, actMsg)
		})
	}
}

func TestGoEncryptNativeDecrypt(t *testing.T) {
	pubkey, privkey, err := naclbox.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	for _, test := range roundtripTests {
		t.Run(test.name, func(t *testing.T) {
			msg := []byte(test.content)
			box, err := sodiumbox.Seal(msg, pubkey)
			assert.NoError(t, err)

			actMsg, err := interop.NativeBoxOpen(box, pubkey, privkey) //nolint: gotypex
			assert.NoError(t, err)
			assert.Equal(t, msg, actMsg)
		})
	}
}
