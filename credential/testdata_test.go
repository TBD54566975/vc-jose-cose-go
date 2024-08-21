package credential

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// These test vectors are taken from the vc-jose-cose spec https://www.w3.org/TR/vc-jose-cose/
const (
	VCExample1            string = "vc-example-1.json"
	VPEnvelopedVCExample1 string = "vp-enveloped-vc-example-1.json"
	VPEnvelopedVPExample1 string = "vp-enveloped-vp-example-1.json"
)

var (
	//go:embed testdata
	testVectors   embed.FS
	vcTestVectors = []string{VCExample1}
	vpTestVectors = []string{VPEnvelopedVCExample1, VPEnvelopedVPExample1}
)

func TestVCVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vcTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vc VerifiableCredential
		err = json.Unmarshal([]byte(gotTestVector), &vc)
		assert.NoError(t, err)

		assert.NoError(t, vc.IsValid())
		assert.False(t, vc.IsEmpty())

		vcBytes, err := json.Marshal(vc)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vcBytes))
	}
}

func TestVPVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vpTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vp VerifiablePresentation
		err = json.Unmarshal([]byte(gotTestVector), &vp)
		assert.NoError(t, err)

		assert.NoError(t, vp.IsValid())
		assert.False(t, vp.IsEmpty())

		vpBytes, err := json.Marshal(vp)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vpBytes))
	}
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
