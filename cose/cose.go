package cose

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/veraison/go-cose"

	"github.com/decentralgabe/vc-jose-cose-go/credential"
)

const (
	VCCOSEType = "application/vc+cose"
	VPCOSEType = "application/vp+cose"
)

// SignVerifiableCredential signs a VerifiableCredential using COSE.
func SignVerifiableCredential(vc credential.VerifiableCredential, key jwk.Key) ([]byte, error) {
	if vc.IsEmpty() {
		return nil, errors.New("VerifiableCredential is empty")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	signer, err := getCOSESigner(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE signer: %w", err)
	}

	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(signer.Algorithm())
	_, _ = message.Headers.Protected.SetType(VCCOSEType)
	message.Headers.Protected[cose.HeaderLabelContentType] = "application/" + credential.VCContentType
	message.Headers.Protected[cose.HeaderLabelKeyID] = []byte(key.KeyID())

	// Convert VC to a JSON object
	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VC to JSON bytes: %w", err)
	}

	message.Payload = vcBytes
	if err = message.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign COSE message: %w", err)
	}

	// Marshal the claims to CBOR
	payload, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VC to CBOR: %w", err)
	}

	return payload, nil
}

// getCOSESigner returns a COSE Signer for the provided JWK key.
func getCOSESigner(key jwk.Key) (cose.Signer, error) {
	var rawKey crypto.Signer
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key from JWK: %w", err)
	}
	var alg cose.Algorithm
	switch key.Algorithm() {
	case jwa.ES256:
		alg = cose.AlgorithmES256
	case jwa.ES384:
		alg = cose.AlgorithmES384
	case jwa.ES512:
		alg = cose.AlgorithmES512
	case jwa.EdDSA:
		alg = cose.AlgorithmEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", key.Algorithm())
	}
	return cose.NewSigner(alg, rawKey)
}

// VerifyVerifiableCredential verifies a COSE-signed VerifiableCredential using the provided key.
func VerifyVerifiableCredential(payload []byte, key jwk.Key) (*credential.VerifiableCredential, error) {
	if payload == nil {
		return nil, errors.New("payload is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Parse the COSE message
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE message: %w", err)
	}

	// Verify the COSE signature
	verifier, err := getCOSEVerifier(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE verifier: %w", err)
	}

	if err = message.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("failed to verify COSE signature: %w", err)
	}

	// Unmarshal the payload
	var vc credential.VerifiableCredential
	if err = json.Unmarshal(message.Payload, &vc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiableCredential: %w", err)
	}

	return &vc, nil
}

// getCOSESigner returns a COSE Signer for the provided JWK key.
func getCOSEVerifier(key jwk.Key) (cose.Verifier, error) {
	var rawKey crypto.PublicKey
	pubKey, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from JWK: %w", err)
	}
	if err = pubKey.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("failed to get raw key from JWK: %w", err)
	}
	var alg cose.Algorithm
	switch key.Algorithm() {
	case jwa.ES256:
		alg = cose.AlgorithmES256
	case jwa.ES384:
		alg = cose.AlgorithmES384
	case jwa.ES512:
		alg = cose.AlgorithmES512
	case jwa.EdDSA:
		alg = cose.AlgorithmEdDSA
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", key.Algorithm())
	}
	return cose.NewVerifier(alg, rawKey)
}

// SignVerifiablePresentation signs a VerifiablePresentation using COSE.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key) ([]byte, error) {
	if vp.IsEmpty() {
		return nil, errors.New("VerifiablePresentation is empty")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	signer, err := getCOSESigner(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE signer: %w", err)
	}

	message := cose.NewSign1Message()
	message.Headers.Protected.SetAlgorithm(signer.Algorithm())
	_, _ = message.Headers.Protected.SetType(VPCOSEType)
	message.Headers.Protected[cose.HeaderLabelContentType] = "application/" + credential.VPContentType
	message.Headers.Protected[cose.HeaderLabelKeyID] = []byte(key.KeyID())

	// Convert VP to a JSON object
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		return nil, fmt.Errorf("failed to convert VP to JSON bytes: %w", err)
	}

	message.Payload = vpBytes
	if err = message.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign COSE message: %w", err)
	}

	// Marshal the claims to CBOR
	payload, err := message.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VP to CBOR: %w", err)
	}

	return payload, nil
}

// VerifyVerifiablePresentation verifies a COSE-signed VerifiablePresentation using the provided key.
func VerifyVerifiablePresentation(payload []byte, key jwk.Key) (*credential.VerifiablePresentation, error) {
	if payload == nil {
		return nil, errors.New("payload is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Parse the COSE message
	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE message: %w", err)
	}

	// Verify the COSE signature
	verifier, err := getCOSEVerifier(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get COSE verifier: %w", err)
	}

	if err = message.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("failed to verify COSE signature: %w", err)
	}

	// Unmarshal the payload
	var vp credential.VerifiablePresentation
	if err = json.Unmarshal(message.Payload, &vp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiablePresentation: %w", err)
	}

	return &vp, nil
}
