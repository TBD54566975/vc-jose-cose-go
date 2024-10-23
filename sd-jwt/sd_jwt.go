package sdjwt

import (
	"encoding/json"
	"errors"
	"fmt"

	sdjwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/TBD54566975/vc-jose-cose-go/jose"
)

const (
	VCSDJWTType = "vc+sd-jwt"
	VPSDJWTType = "vp+sd-jwt"
)

type DisclosedClaims map[string]any

// SignVerifiableCredential signs a VerifiableCredential using SD-JWT.
func SignVerifiableCredential(vc credential.VerifiableCredential, key jwk.Key, disclosableFields []string) (*string, error) {
	if vc.IsEmpty() {
		return nil, errors.New("VerifiableCredential is empty")
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
		"typ": VCSDJWTType,
		"cty": credential.VCContentType,
		"alg": key.Algorithm().String(),
		"kid": key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Create disclosures for the specified fields
	disclosures := make([]disclosure.Disclosure, 0)
	for _, field := range disclosableFields {
		value, ok := vcMap[field]
		if !ok {
			continue // Skip if field doesn't exist
		}
		disc, err := disclosure.NewFromObject(field, value, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create disclosure for %s: %w", field, err)
		}
		disclosures = append(disclosures, *disc)
	}

	// Sign the payload as a JWS
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	// Create SD-JWT with disclosures
	sdJWT, err := sdjwt.NewFromComponents(parsedJWT.Protected, parsedJWT.Payload, parsedJWT.Signature, disclosuresToStrings(disclosures), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from JWT: %w", err)
	}

	// Create disclosures for the specified fields
	for _, field := range disclosableFields {
		value, ok := vcMap[field]
		if !ok {
			continue // Skip if field doesn't exist
		}
		disc, err := disclosure.NewFromObject(field, value, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create disclosure for %s: %w", field, err)
		}
		sdJWT.Disclosures = append(sdJWT.Disclosures, *disc)
	}

	// Generate the final SD-JWT token
	token, err := sdJWT.Token()
	if err != nil {
		return nil, fmt.Errorf("failed to generate SD-JWT token: %w", err)
	}

	return token, nil
}

// VerifyVerifiableCredential verifies a VerifiableCredential SD-JWT using the provided key.
func VerifyVerifiableCredential(sdJWT string, key jwk.Key) (*credential.VerifiableCredential, []disclosure.Disclosure, error) {
	if sdJWT == "" {
		return nil, nil, errors.New("SD-JWT is empty")
	}
	parsedSDJWT, err := sdjwt.New(sdJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}
	if parsedSDJWT == nil {
		return nil, nil, errors.New("parsed SD-JWT is nil")
	}
	if parsedSDJWT.KbJwt != nil {
		return nil, nil, errors.New("kbJWT not yet supported")
	}
	if parsedSDJWT.Head == nil || len(parsedSDJWT.Head) == 0 {
		return nil, nil, errors.New("head should not be empty")
	}
	if parsedSDJWT.Body == nil {
		return nil, nil, errors.New("body should not be empty")
	}
	if parsedSDJWT.Signature == "" {
		return nil, nil, errors.New("signature should not be empty")
	}

	token, err := parsedSDJWT.Token()
	if err != nil || token == nil {
		return nil, nil, fmt.Errorf("failed to get token from SD-JWT: %w", err)
	}

	// Verify the JWT signature
	payload, err := jws.Verify([]byte(*token), jws.WithKey(key.Algorithm(), key))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify JWT signature: %w", err)
	}

	// Parse the payload into a VerifiableCredential
	var vc credential.VerifiableCredential
	if err = json.Unmarshal(payload, &vc); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal payload into VerifiableCredential: %w", err)
	}

	return &vc, parsedSDJWT.Disclosures, nil
}

// SignVerifiablePresentation signs a VerifiablePresentation as an SD-JWT using the provided key.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, key jwk.Key) (*string, error) {
	if vp.IsEmpty() {
		return nil, errors.New("VerifiablePresentation is empty")
	}

	jwt, err := jose.SignVerifiablePresentation(vp, key)
	if err != nil {
		return nil, fmt.Errorf("failed to sign VerifiablePresentation: %w", err)
	}

	sdJWT, err := sdjwt.New(jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from JWT: %w", err)
	}

	return sdJWT.Token()
}

// VerifyVerifiablePresentation verifies a VerifiablePresentation SD-JWT using the provided key.
func VerifyVerifiablePresentation(sdJWT string, key jwk.Key) (*credential.VerifiablePresentation, DisclosedClaims, error) {
	if sdJWT == "" {
		return nil, nil, errors.New("SD-JWT is empty")
	}
	parsedSDJWT, err := sdjwt.New(sdJWT)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}
	if parsedSDJWT == nil {
		return nil, nil, errors.New("parsed SD-JWT is nil")
	}
	if parsedSDJWT.KbJwt != nil {
		return nil, nil, errors.New("kbJWT not yet supported")
	}
	if parsedSDJWT.Head == nil || len(parsedSDJWT.Head) == 0 {
		return nil, nil, errors.New("head should not be empty")
	}
	if parsedSDJWT.Body == nil {
		return nil, nil, errors.New("body should not be empty")
	}
	if parsedSDJWT.Signature == "" {
		return nil, nil, errors.New("signature should not be empty")
	}

	token, err := parsedSDJWT.Token()
	if err != nil || token == nil {
		return nil, nil, fmt.Errorf("failed to get token from SD-JWT: %w", err)
	}

	disclosedClaims, err := parsedSDJWT.GetDisclosedClaims()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get disclosed claims from SD-JWT: %w", err)
	}

	vp, err := jose.VerifyVerifiablePresentation(*token, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify SD-JWT: %w", err)
	}

	return vp, disclosedClaims, nil
}
