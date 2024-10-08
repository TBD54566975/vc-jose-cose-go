package jose

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/TBD54566975/vc-jose-cose-go/util"
)

func Test_Sign_Verify_VerifiableCredential(t *testing.T) {
	tests := []struct {
		name  string
		curve jwa.EllipticCurveAlgorithm
	}{
		{"EC P-256", jwa.P256},
		{"EC P-384", jwa.P384},
		{"EC P-521", jwa.P521},
		{"OKP EdDSA", jwa.Ed25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, privKey, err := util.GenerateKeyByEllipticCurveAlgorithm(tt.curve)
			require.NoError(t, err)

			key, err := jwk.FromRaw(privKey)
			require.NoError(t, err)

			vc := &credential.VerifiableCredential{
				Context:   []string{"https://www.w3.org/2018/credentials/v1"},
				ID:        "http://example.edu/credentials/1872",
				Type:      []string{"VerifiableCredential"},
				Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
				ValidFrom: "2010-01-01T19:23:24Z",
				CredentialSubject: map[string]any{
					"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
				},
			}

			jwt, err := SignVerifiableCredential(vc, key)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)

			// Verify the VC
			verifiedVC, err := VerifyVerifiableCredential(jwt, key)
			require.NoError(t, err)
			assert.Equal(t, vc.ID, verifiedVC.ID)
			assert.Equal(t, vc.Issuer.ID, verifiedVC.Issuer.ID)
		})
	}
}

func Test_Sign_Verify_VerifiablePresentation(t *testing.T) {
	tests := []struct {
		name  string
		curve jwa.EllipticCurveAlgorithm
	}{
		{"EC P-256", jwa.P256},
		{"EC P-384", jwa.P384},
		{"EC P-521", jwa.P521},
		{"OKP EdDSA", jwa.Ed25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, privKey, err := util.GenerateKeyByEllipticCurveAlgorithm(tt.curve)
			require.NoError(t, err)

			key, err := jwk.FromRaw(privKey)
			require.NoError(t, err)

			vp := credential.VerifiablePresentation{
				Context: []string{"https://www.w3.org/2018/credentials/v1"},
				ID:      "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
				Type:    []string{"VerifiablePresentation"},
				Holder:  credential.NewIssuerHolderFromString("did:example:ebfeb1f712ebc6f1c276e12ec21"),
			}

			jwt, err := SignVerifiablePresentation(vp, key)
			require.NoError(t, err)
			assert.NotEmpty(t, jwt)

			// Verify the VP
			verifiedVP, err := VerifyVerifiablePresentation(jwt, key)
			require.NoError(t, err)
			assert.Equal(t, vp.ID, verifiedVP.ID)
			assert.Equal(t, vp.Holder.ID, verifiedVP.Holder.ID)
		})
	}
}
