package jose

import (
	"errors"
	"fmt"
	"time"

	"github.com/goccy/go-json"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
)

const (
	VCJOSEType = "vc+jwt"
	VPJOSEType = "vp+jwt"
)

// SignVerifiableCredential dynamically signs a VerifiableCredential based on the key type.
func SignVerifiableCredential(vc credential.VerifiableCredential, key jwk.Key) (*string, error) {
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
	// Convert VC to a map
	vcMap, err := vc.ToMap()
	if err != nil {
		return nil, fmt.Errorf("failed to convert VC to map: %w", err)
	}

	// Add standard claims
	if !vc.Issuer.IsEmpty() {
		vcMap["iss"] = vc.Issuer.ID()
	}
	if vc.ID != "" {
		vcMap["jti"] = vc.ID
	}
	if vc.ValidFrom != "" {
		vcMap["iat"] = vc.ValidFrom
	}
	if vc.ValidUntil != "" {
		vcMap["exp"] = vc.ValidUntil
	}

	// Marshal the claims to JSON
	payload, err := json.Marshal(vcMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		"typ": VCJOSEType,
		"cty": credential.VCContentType,
		"alg": key.Algorithm().String(),
		"kid": key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the payload
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	result := string(signed)
	return &result, nil
}

// VerifyVerifiableCredential verifies a VerifiableCredential JWT using the provided key.
func VerifyVerifiableCredential(jwt string, key jwk.Key) (*credential.VerifiableCredential, error) {
	if jwt == "" {
		return nil, errors.New("JWT is required")
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

	// Verify the JWT signature and get the payload
	payload, err := jws.Verify([]byte(jwt), jws.WithKey(key.Algorithm(), key))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	// Unmarshal the payload into VerifiableCredential
	var vc credential.VerifiableCredential
	if err := json.Unmarshal(payload, &vc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiableCredential: %w", err)
	}

	return &vc, nil
}

// SignVerifiablePresentation dynamically signs a VerifiablePresentation based on the key type.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key) (string, error) {
	if vp.IsEmpty() {
		return "", errors.New("VerifiablePresentation is empty")
	}
	if key == nil {
		return "", errors.New("key is required")
	}
	if key.KeyID() == "" {
		return "", errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return "", errors.New("key algorithm is required")
	}

	var alg jwa.SignatureAlgorithm
	kty := key.KeyType()
	switch kty {
	case jwa.EC:
		crv, ok := key.Get("crv")
		if !ok || crv == nil {
			return "", fmt.Errorf("invalid or missing 'crv' parameter")
		}
		crvAlg := crv.(jwa.EllipticCurveAlgorithm)
		switch crvAlg {
		case jwa.P256:
			alg = jwa.ES256
		case jwa.P384:
			alg = jwa.ES384
		case jwa.P521:
			alg = jwa.ES512
		default:
			return "", fmt.Errorf("unsupported curve: %s", crvAlg.String())
		}
	case jwa.OKP:
		alg = jwa.EdDSA
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	// Convert the VerifiablePresentation to a map for manipulation
	vpMap := make(map[string]any)
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		return "", err
	}
	if err = json.Unmarshal(vpBytes, &vpMap); err != nil {
		return "", err
	}

	// Add standard claims
	if !vp.Holder.IsEmpty() {
		vpMap["iss"] = vp.Holder.ID()
	}
	if vp.ID != "" {
		vpMap["jti"] = vp.ID
	}

	vpMap["iat"] = time.Now().Unix()

	// TODO(gabe): allow this to be configurable
	vpMap["exp"] = time.Now().Add(time.Hour * 24).Unix()

	// Marshal the claims to JSON
	payload, err := json.Marshal(vpMap)
	if err != nil {
		return "", err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		"typ": VPJOSEType,
		"cty": credential.VPContentType,
		"alg": alg.String(),
		"kid": key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return "", err
		}
	}

	// Sign the payload
	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// VerifyVerifiablePresentation verifies a VerifiablePresentation JWT using the provided key.
func VerifyVerifiablePresentation(jwt string, key jwk.Key) (*credential.VerifiablePresentation, error) {
	if jwt == "" {
		return nil, errors.New("JWT is required")
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

	// Verify the JWT signature and get the payload
	payload, err := jws.Verify([]byte(jwt), jws.WithKey(key.Algorithm(), key))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	// Unmarshal the payload into VerifiablePresentation
	var vp credential.VerifiablePresentation
	if err := json.Unmarshal(payload, &vp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiablePresentation: %w", err)
	}

	return &vp, nil
}
