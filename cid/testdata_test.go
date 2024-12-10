package cid

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

const (
	VMExample1 string = "vm-ed25519.json"
	VMExample2 string = "vm-p256.json"
	VMExample3 string = "vm-p384.json"
	VMExample4 string = "vm-p521.json"
)

var (
	//go:embed testdata
	testVectors   embed.FS
	vmTestVectors = []string{VMExample1, VMExample2, VMExample3, VMExample4}
)

func TestVMVectors(t *testing.T) {
	// round trip serialize and de-serialize from json to our object model
	for _, tv := range vmTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		var vm VerificationMethod
		err = json.Unmarshal([]byte(gotTestVector), &vm)
		assert.NoError(t, err)

		vmBytes, err := json.Marshal(vm)
		assert.NoError(t, err)
		assert.JSONEq(t, gotTestVector, string(vmBytes))
	}
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
