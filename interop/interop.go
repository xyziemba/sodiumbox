// Package interop provides methods for communicating with libsodium.
// You shouldn't use it. It's only here for use by sodiumbox's tests.
// It's only been tested on Mac.
package interop

/*
#cgo LDFLAGS: -lsodium
#include "sodium.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	"unsafe"
)

func init() {
	if C.sodium_init() < 0 {
		log.Panic("unable to init libsodium")
	}
}

// NativeBoxSeal provides a wrapper around crypto_box_seal
func NativeBoxSeal(msg []byte, recipientPubkey *[C.crypto_box_PUBLICKEYBYTES]byte) (box []byte) {
	fmt.Println("asdf")
	fmt.Println(C.crypto_box_PUBLICKEYBYTES)
	boxLen := len(msg) + C.crypto_box_SEALBYTES

	cBox := C.malloc(C.size_t(boxLen))
	defer C.free(cBox)

	cMsg := C.CBytes(msg) //nolint: vet
	defer C.free(cMsg)

	cPubkey := C.CBytes(recipientPubkey[:]) //nolint: vet
	defer C.free(cPubkey)

	C.crypto_box_seal((*C.uchar)(cBox), (*C.uchar)(cMsg), C.ulonglong(len(msg)), (*C.uchar)(cPubkey))
	box = C.GoBytes(cBox, C.int(boxLen))
	return
}

// NativeBoxOpen provides a wrapper around crypto_box_seal_open
func NativeBoxOpen(box []byte, pubkey *[C.crypto_box_PUBLICKEYBYTES]byte, privkey *[C.crypto_box_SECRETKEYBYTES]byte) (msg []byte, err error) {
	boxLen := len(box)
	msgLen := boxLen - C.crypto_box_SEALBYTES

	cMsg := (*C.uchar)(C.malloc(C.size_t(msgLen)))
	defer C.free(unsafe.Pointer(cMsg))

	cBox := (*C.uchar)(C.CBytes(box)) //nolint: vet
	defer C.free(unsafe.Pointer(cBox))

	cPubkey := (*C.uchar)(C.CBytes(pubkey[:])) //nolint:vet
	defer C.free(unsafe.Pointer(cPubkey))

	cPrivkey := (*C.uchar)(C.CBytes(privkey[:])) //nolint: vet
	defer C.free(unsafe.Pointer(cPrivkey))

	ret := C.crypto_box_seal_open(cMsg, cBox, C.ulonglong(boxLen), cPubkey, cPrivkey)
	if ret != 0 {
		return nil, errors.New("sodiumbox/interop: message corrupt or not intended for this recipient")
	}

	msg = C.GoBytes(unsafe.Pointer(cMsg), C.int(msgLen))
	if len(msg) == 0 {
		msg = nil
	}
	return
}
