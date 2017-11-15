package sodiumbox_test

import (
	"crypto/rand"
	"testing"

	"github.com/xyziemba/sodiumbox"

	"github.com/stretchr/testify/assert"
	naclbox "golang.org/x/crypto/nacl/box"
)

var roundtripTests = []struct {
	name    string
	content []byte
}{
	{"Nil", nil},
	{"Single", []byte("A")},
	{"String", []byte("This is s string!")},
	{"Unicode", []byte("🤠")},
}

func TestRoundtrip(t *testing.T) {
	pubkey, privkey, err := naclbox.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	for _, test := range roundtripTests {
		t.Run(test.name, func(t *testing.T) {
			msg := []byte(test.content)

			box, err := sodiumbox.Seal(msg, pubkey)
			assert.NoError(t, err)
			assert.Equal(t, len(msg)+sodiumbox.Overhead, len(box))

			actMsg, err := sodiumbox.Open(box, pubkey, privkey)
			assert.NoError(t, err)
			assert.Equal(t, msg, actMsg)
		})
	}
}
