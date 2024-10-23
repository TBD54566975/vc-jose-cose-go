package sdjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/TBD54566975/vc-jose-cose-go/util"
)

func Test_Sign_Verify_VerifiableCredential(t *testing.T) {
	simpleVC := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		},
	}

	detailVC := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"address": map[string]any{
				"streetAddress": "123 Main St",
				"city":          "Anytown",
				"country":       "US",
			},
			"details": []any{
				"Detail 1",
				"Detail 2",
			},
		},
	}

	tests := []struct {
		name            string
		curve           jwa.EllipticCurveAlgorithm
		disclosurePaths []DisclosurePath
		vc              *credential.VerifiableCredential
		verifyFields    func(*testing.T, *credential.VerifiableCredential)
	}{
		{
			name:  "EC P-256 with simple credential subject disclosure",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
		{
			name:  "EC P-256 with complex nested disclosures",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"credentialSubject.id",
				"credentialSubject.address.streetAddress",
				"credentialSubject.details[0]",
			},
			vc: &detailVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
				address := vc.CredentialSubject["address"].(map[string]any)
				assert.Equal(t, "123 Main St", address["streetAddress"])
				assert.Equal(t, "Anytown", address["city"])
				details := vc.CredentialSubject["details"].([]any)
				assert.Equal(t, "Detail 1", details[0])
			},
		},
		{
			name:  "EC P-256 with top level disclosures",
			curve: jwa.P256,
			disclosurePaths: []DisclosurePath{
				"id",
				"validFrom",
				"credentialSubject.id",
			},
			vc: &simpleVC,
			verifyFields: func(t *testing.T, vc *credential.VerifiableCredential) {
				assert.Equal(t, "https://example.edu/credentials/1872", vc.ID)
				assert.Equal(t, "2010-01-01T19:23:24Z", vc.ValidFrom)
				assert.Equal(t, "did:example:ebfeb1f712ebc6f1c276e12ec21", vc.CredentialSubject["id"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate issuer key
			issuerKey, err := util.GenerateJWKWithAlgorithm(tt.curve)
			require.NoError(t, err)

			// Sign the credential
			sdJwt, err := SignVerifiableCredential(*tt.vc, tt.disclosurePaths, issuerKey)
			require.NoError(t, err)
			require.NotNil(t, sdJwt)

			// Verify the credential
			verifiedVC, err := VerifyVerifiableCredential(*sdJwt, issuerKey)
			require.NoError(t, err)
			require.NotNil(t, verifiedVC)

			// Verify standard fields
			assert.Equal(t, tt.vc.Context, verifiedVC.Context)
			assert.Equal(t, tt.vc.Type, verifiedVC.Type)
			assert.Equal(t, tt.vc.Issuer, verifiedVC.Issuer)

			// Apply any test-specific verification
			if tt.verifyFields != nil {
				tt.verifyFields(t, verifiedVC)
			}

			// Verify validation fails with wrong key
			wrongKey, err := util.GenerateJWKWithAlgorithm(tt.curve)
			require.NoError(t, err)
			_, err = VerifyVerifiableCredential(*sdJwt, wrongKey)
			assert.Error(t, err)
		})
	}
}
