package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyToBytes(t *testing.T) {
	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType), func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}

	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(&pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(&priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}
}

func TestSECP256k1Conversions(t *testing.T) {
	pk, sk, err := GenerateSECP256k1Key()
	assert.NoError(t, err)

	ecdsaPK := pk.ToECDSA()
	ecdsaSK := sk.ToECDSA()

	gotPK := SECP256k1ECDSAPubKeyToSECP256k1(*ecdsaPK)
	gotSK := SECP256k1ECDSASPrivKeyToSECP256k1(*ecdsaSK)

	assert.Equal(t, pk, gotPK)
	assert.Equal(t, sk, gotSK)
}
