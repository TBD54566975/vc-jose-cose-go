package jose

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestSignJOSE(t *testing.T) {
	// Create a sample VerifiableCredential
	vc := &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "http://example.edu/credentials/1872",
		Type:         []string{"VerifiableCredential"},
		Issuer:       credential.IssuerHolder{ID: "https://example.edu/issuers/565049"},
		IssuanceDate: time.Now(),
		CredentialSubject: map[string]interface{}{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"alumniOf": map[string]interface{}{
				"id":   "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name": "Example University",
			},
		},
	}

	// Generate a test key
	key, err := jwk.FromRaw([]byte("test-key"))
	assert.NoError(t, err)

	// Test SignJOSE with different algorithms
	algorithms := []jwa.SignatureAlgorithm{jwa.EdDSA, jwa.ES256, jwa.ES256K}
	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			signed, err := SignVerifiableCredential(vc, key, alg)
			assert.NoError(t, err)
			assert.NotEmpty(t, signed)

			// Verify the signed JWT
			token, err := jws.Parse([]byte(signed))
			assert.NoError(t, err)

			headers := token.Signatures()[0].ProtectedHeaders()
			assert.Equal(t, VCJOSEType, headers.Type())
			assert.Equal(t, alg.String(), headers.Algorithm())

			payload, err := token.Payload()
			assert.NoError(t, err)

			var claims map[string]interface{}
			err = json.Unmarshal(payload, &claims)
			assert.NoError(t, err)

			assert.Equal(t, vc.IssuerID(), claims["iss"])
			assert.NotNil(t, claims["nbf"])
			assert.NotNil(t, claims["vc"])
		})
	}
}

func TestSignJOSEWithEd25519(t *testing.T) {
	vc := &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "http://example.edu/credentials/1872",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "https://example.edu/issuers/565049",
		IssuanceDate: time.Now().Format(time.RFC3339),
	}

	key, err := jwk.FromRaw([]byte("test-key"))
	assert.NoError(t, err)

	signed, err := SignJOSEWithEd25519(vc, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	token, err := jws.Parse([]byte(signed))
	assert.NoError(t, err)
	assert.Equal(t, jwa.EdDSA.String(), token.Signatures()[0].ProtectedHeaders().Algorithm())
}

func TestSignJOSEWithES256(t *testing.T) {
	vc := &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "http://example.edu/credentials/1872",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "https://example.edu/issuers/565049",
		IssuanceDate: time.Now().Format(time.RFC3339),
	}

	key, err := jwk.FromRaw([]byte("test-key"))
	assert.NoError(t, err)

	signed, err := SignJOSEWithES256(vc, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	token, err := jws.Parse([]byte(signed))
	assert.NoError(t, err)
	assert.Equal(t, jwa.ES256.String(), token.Signatures()[0].ProtectedHeaders().Algorithm())
}

func TestSignJOSEWithSecp256k1(t *testing.T) {
	vc := &credential.VerifiableCredential{
		Context:      []string{"https://www.w3.org/2018/credentials/v1"},
		ID:           "http://example.edu/credentials/1872",
		Type:         []string{"VerifiableCredential"},
		Issuer:       "https://example.edu/issuers/565049",
		IssuanceDate: time.Now().Format(time.RFC3339),
	}

	key, err := jwk.FromRaw([]byte("test-key"))
	assert.NoError(t, err)

	signed, err := SignJOSEWithSecp256k1(vc, key)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	token, err := jws.Parse([]byte(signed))
	assert.NoError(t, err)
	assert.Equal(t, jwa.ES256K.String(), token.Signatures()[0].ProtectedHeaders().Algorithm())
}

func TestSignJOSEErrors(t *testing.T) {
	key, _ := jwk.FromRaw([]byte("test-key"))

	t.Run("nil VerifiableCredential", func(t *testing.T) {
		_, err := SignVerifiableCredential(nil, key, jwa.EdDSA)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "verifiable credential is nil")
	})

	t.Run("invalid key", func(t *testing.T) {
		vc := &credential.VerifiableCredential{}
		invalidKey, _ := jwk.FromRaw([]byte("invalid"))
		_, err := SignVerifiableCredential(vc, invalidKey, jwa.EdDSA)
		assert.Error(t, err)
	})
}
