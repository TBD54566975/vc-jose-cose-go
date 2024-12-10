package vc_jose_cose_go

import (
	"fmt"
	"github.com/TBD54566975/vc-jose-cose-go/cid"
	"github.com/TBD54566975/vc-jose-cose-go/util"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGenerateKeys is used to generate sample cid document verification methods
func TestGenerateKeys(t *testing.T) {
	t.Skip("skipping test as it is not needed except for local testing")

	tests := []struct {
		name  string
		curve jwa.EllipticCurveAlgorithm
		kid   string
	}{
		{"EC P-256", jwa.P256, "key-1"},
		{"EC P-384", jwa.P384, "key-2"},
		{"EC P-521", jwa.P521, "key-3"},
		{"OKP EdDSA", jwa.Ed25519, "key-4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := util.GenerateJWK(tt.curve)
			require.NoError(t, err)
			assert.NotNil(t, key)

			pubKey, err := key.PublicKey()
			require.NoError(t, err)
			assert.NotNil(t, pubKey)

			id := "https://example.issuer/6c427e8392ab4057b93356fbb9022ecb"
			vm := cid.VerificationMethod{
				ID:           fmt.Sprintf("%s#%s", id, tt.kid),
				Type:         cid.TypeJSONWebKey,
				Controller:   util.SingleOrArray[string]{id},
				PublicKeyJWK: pubKey,
				SecretKeyJWK: key,
			}

			vmJSONBytes, err := json.Marshal(vm)
			require.NoError(t, err)
			t.Logf("\n%s\n", string(vmJSONBytes))
		})
	}
}

func TestKeyToBytes(t *testing.T) {
	for _, keyType := range util.GetSupportedKeyTypes() {
		t.Run(string(keyType), func(t *testing.T) {
			pub, priv, err := util.GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := util.PubKeyToBytes(pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := util.BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := util.PrivKeyToBytes(priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := util.BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := util.GetKeyTypeFromPrivateKey(priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}

	for _, keyType := range util.GetSupportedKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(t *testing.T) {
			pub, priv, err := util.GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := util.PubKeyToBytes(&pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := util.BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := util.PrivKeyToBytes(&priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := util.BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := util.GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}
}

func TestSECP256k1Conversions(t *testing.T) {
	pk, sk, err := util.GenerateSECP256k1Key()
	assert.NoError(t, err)

	ecdsaPK := pk.ToECDSA()
	ecdsaSK := sk.ToECDSA()

	gotPK := util.SECP256k1ECDSAPubKeyToSECP256k1(*ecdsaPK)
	gotSK := util.SECP256k1ECDSASPrivKeyToSECP256k1(*ecdsaSK)

	assert.Equal(t, pk, gotPK)
	assert.Equal(t, sk, gotSK)
}
