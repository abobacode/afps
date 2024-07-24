// NOTE: In production, please implement your content key logic instead of Random Content Key
package main

import (
	"crypto/md5"
	"math/rand"

	"github.com/abobacode/afps/ksm"
)

type RandomContentKey struct {
}

// Implement FetchContentKey func
func (RandomContentKey) FetchContentKey(assetID []byte) ([]byte, []byte, error) {
	return generateDummyKeyIVPair(assetID)
}

// Implement FetchContentKeyDuration func
func (RandomContentKey) FetchContentKeyDuration(assetID []byte) (*ksm.CkcContentKeyDurationBlock, error) {

	LeaseDuration := rand.Uint32()  // The duration of the lease, if any, in seconds.
	RentalDuration := rand.Uint32() // The duration of the rental, if any, in seconds.

	return ksm.NewCkcContentKeyDurationBlock(LeaseDuration, RentalDuration), nil
}

func generateDummyKeyIVPair(assetID []byte) ([]byte, []byte, error) {
	dummyKey := make([]byte, 16)
	dummyIV := make([]byte, 16)
	rand.Read(dummyIV)

	if len(assetID) == 0 {
		rand.Read(dummyKey)
		return dummyKey, dummyIV, nil
	}
	// NOTE: Here is to implement your key generator.
	generator := md5.New()
	generator.Write(assetID)
	dummyKey = generator.Sum(nil)
	return dummyKey, dummyIV, nil
}
