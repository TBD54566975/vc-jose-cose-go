package jose

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
)

const (
	VCJOSEType = "vc+jwt"
	VPJOSEType = "vp+jwt"
	VCJWTTyp   = "JWT"
	VCJWTAlg   = "alg"
	VCJWTKid   = "kid"
)

// SignVerifiableCredential dynamically signs a VerifiableCredential based on the key type.
func SignVerifiableCredential(vc *credential.VerifiableCredential, key jwk.Key) (string, error) {
	var alg jwa.SignatureAlgorithm

	kty := key.KeyType()
	switch kty {
	case jwa.EC:
		crv, ok := key.Get("crv")
		if !ok || crv == nil {
			return "", fmt.Errorf("invalid or missing 'crv' parameter")
		}
		crvStr, ok := crv.(string)
		if !ok {
			return "", fmt.Errorf("'crv' parameter is not a string")
		}
		switch crvStr {
		case jwa.P256.String():
			alg = jwa.ES256
		case jwa.P384.String():
			alg = jwa.ES384
		case jwa.P521.String():
			alg = jwa.ES512
		default:
			return "", fmt.Errorf("unsupported curve: %s", crvStr)
		}
	case jwa.OKP:
		alg = jwa.EdDSA
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	return signVerifiableCredential(vc, key, alg)
}

// VerifyVerifiableCredential verifies a VerifiableCredential JWT using the provided key.
func VerifyVerifiableCredential(jwt string, key jwk.Key) (*credential.VerifiableCredential, error) {
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

// SignVerifiableCredential dynamically signs a VerifiableCredential using the specified algorithm,
// ensuring that all fields from the vc object are included at the top level in the JWT claims.
func signVerifiableCredential(vc *credential.VerifiableCredential, key jwk.Key, alg jwa.SignatureAlgorithm) (string, error) {
	// Marshal the VerifiableCredential to a map
	vcMap := make(map[string]any)
	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(vcBytes, &vcMap); err != nil {
		return "", err
	}

	// Add standard claims
	if vc.Issuer != nil {
		vcMap["iss"] = vc.Issuer.ID
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
		if err := jwsHeaders.Set(k, v); err != nil {
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

// SignJOSE dynamically signs a VerifiablePresentation based on the key type.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key) (string, error) {
	var alg jwa.SignatureAlgorithm

	kty := key.KeyType()
	switch kty {
	case jwa.EC:
		crv, ok := key.Get("crv")
		if !ok || crv == nil {
			return "", fmt.Errorf("invalid or missing 'crv' parameter")
		}
		crvStr, ok := crv.(string)
		if !ok {
			return "", fmt.Errorf("'crv' parameter is not a string")
		}
		switch crvStr {
		case jwa.P256.String():
			alg = jwa.ES256
		case jwa.P384.String():
			alg = jwa.ES384
		case jwa.P521.String():
			alg = jwa.ES512
		default:
			return "", fmt.Errorf("unsupported curve: %s", crvStr)
		}
	case jwa.OKP:
		alg = jwa.EdDSA
	default:
		return "", fmt.Errorf("unsupported key type: %s", kty)
	}

	return signVerifiablePresentation(vp, key, alg)
}

// VerifyVerifiablePresentation verifies a VerifiablePresentation JWT using the provided key.
func VerifyVerifiablePresentation(jwt string, key jwk.Key) (*credential.VerifiablePresentation, error) {
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

// SignVerifiablePresentation dynamically signs a VerifiablePresentation using the specified algorithm.
func signVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key, alg jwa.SignatureAlgorithm) (string, error) {
	// Convert the VerifiablePresentation to a map for manipulation
	vpMap := make(map[string]any)
	vpBytes, err := json.Marshal(vp)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(vpBytes, &vpMap); err != nil {
		return "", err
	}

	// Add standard claims
	if vp.Holder != nil {
		vpMap["iss"] = vp.Holder.ID
	}
	if vp.ID != "" {
		vpMap["jti"] = vp.ID
	}

	vpMap["iat"] = time.Now().Unix()

	// TODO(gabe): allow this to beconfigurable
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
		if err := jwsHeaders.Set(k, v); err != nil {
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
