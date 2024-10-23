package sdjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/TBD54566975/vc-jose-cose-go/util"
)

func Test_Sign_Verify_VerifiableCredential_SDJWT(t *testing.T) {
	tests := []struct {
		name  string
		curve jwa.EllipticCurveAlgorithm
	}{
		{"EC P-256", jwa.P256},
		// {"EC P-384", jwa.P384},
		// {"EC P-521", jwa.P521},
		// {"OKP EdDSA", jwa.Ed25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := util.GenerateJWKWithAlgorithm(tt.curve)
			require.NoError(t, err)

			vc := &credential.VerifiableCredential{
				Context:   []string{"https://www.w3.org/2018/credentials/v1"},
				ID:        "https://example.edu/credentials/1872",
				Type:      []string{"VerifiableCredential"},
				Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
				ValidFrom: "2010-01-01T19:23:24Z",
				CredentialSubject: map[string]any{
					"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
				},
			}
			disclosableFields := []string{"id"}

			sdJWT, err := SignVerifiableCredential(*vc, key, disclosableFields)
			require.NoError(t, err)
			require.NotNil(t, sdJWT)

			// Verify the SD-JWT
			parsedVC, disclosedClaims, err := VerifyVerifiableCredential(*sdJWT, key)
			require.NoError(t, err)
			require.NotEmpty(t, parsedVC)
			require.NotEmpty(t, disclosedClaims)

			// Check if the parsed VC matches the original
			assert.Equal(t, vc.Context, parsedVC.Context)
			assert.Equal(t, vc.ID, parsedVC.ID)
			assert.Equal(t, vc.Type, parsedVC.Type)
			assert.Equal(t, vc.Issuer, parsedVC.Issuer)
			assert.Equal(t, vc.ValidFrom, parsedVC.ValidFrom)

			// Check if the disclosable field was correctly disclosed
			// assert.Contains(t, disclosedClaims, "credentialSubject")
			// subjectClaims, ok := disclosedClaims["credentialSubject"].(map[string]interface{})
			// require.True(t, ok)
			// assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", subjectClaims["id"])
		})
	}
}
