package sdjwt

import (
	"crypto"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/goccy/go-json"

	sdjwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
)

const (
	VCSDJWTType = "vc+sd-jwt"
	VPSDJWTType = "vp+sd-jwt"
)

// DisclosurePath represents a path to a field that should be made selectively disclosable
// Example paths:
// - "credentialSubject.id"
// - "credentialSubject.address.streetAddress"
// - "credentialSubject.nationalities[0]" for array element
type DisclosurePath string

// SignVerifiableCredential creates an SD-JWT from a VerifiableCredential, making specified fields
// selectively disclosable according to the provided paths.
func SignVerifiableCredential(vc credential.VerifiableCredential, disclosurePaths []DisclosurePath, key jwk.Key) (*string, error) {
	if vc.IsEmpty() {
		return nil, errors.New("VerifiableCredential is empty")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Convert VC to a map for manipulation
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

	// Process disclosures
	disclosures := make([]disclosure.Disclosure, 0, len(disclosurePaths))
	processedMap, err := processDisclosures(vcMap, disclosurePaths, &disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosures: %w", err)
	}
	vcMap = processedMap

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

	// Sign the JWS issuer key
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	// Combine JWT with disclosures
	sdJWTParts := []string{(string)(signed)}
	for _, d := range disclosures {
		sdJWTParts = append(sdJWTParts, d.EncodedValue)
	}

	sdJwt := fmt.Sprintf("%s~", strings.Join(sdJWTParts, "~"))
	return &sdJwt, nil
}

// processDisclosures traverses the credential map and creates disclosures for specified paths
func processDisclosures(data map[string]any, paths []DisclosurePath, disclosures *[]disclosure.Disclosure) (map[string]any, error) {
	result := make(map[string]any)
	for k, v := range data {
		result[k] = v
	}
	for _, path := range paths {
		parts := strings.Split(string(path), ".")
		if err := processPath(result, parts, disclosures); err != nil {
			return nil, fmt.Errorf("failed to process path %s: %w", path, err)
		}
	}
	return result, nil
}

// processPath handles a single disclosure path
func processPath(data map[string]any, pathParts []string, disclosures *[]disclosure.Disclosure) error {
	if len(pathParts) == 0 {
		return nil
	}

	// Split path part into field name and optional array index
	parts := strings.SplitN(pathParts[0], "[", 2)
	field := parts[0]
	arrayIndex := -1

	// Check if we have an array index
	if len(parts) == 2 {
		// Remove trailing ']'
		indexStr := strings.TrimSuffix(parts[1], "]")
		var err error
		arrayIndex, err = strconv.Atoi(indexStr)
		if err != nil {
			return fmt.Errorf("invalid array index '%s' in path: %s", indexStr, pathParts[0])
		}
	}

	value, exists := data[field]
	if !exists {
		return fmt.Errorf("field not found: %s", field)
	}

	// If this is the last path part, create the disclosure
	if len(pathParts) == 1 {
		if arrayIndex >= 0 {
			arr, ok := value.([]any)
			if !ok {
				return fmt.Errorf("field %s is not an array", field)
			}
			if arrayIndex >= len(arr) {
				return fmt.Errorf("array index %d out of bounds for field %s", arrayIndex, field)
			}
			// Create disclosure for array element
			d, err := disclosure.NewFromArrayElement(arr[arrayIndex], nil)
			if err != nil {
				return err
			}
			*disclosures = append(*disclosures, *d)

			// Replace with digest
			arr[arrayIndex] = map[string]any{
				"...": string(d.Hash(crypto.SHA256.New())),
			}
			data[field] = arr
		} else {
			// Create disclosure for object property
			d, err := disclosure.NewFromObject(field, value, nil)
			if err != nil {
				return err
			}
			*disclosures = append(*disclosures, *d)

			// Add hash to _sd array
			hash := d.Hash(crypto.SHA256.New())
			if data["_sd"] == nil {
				data["_sd"] = []string{string(hash)}
			} else {
				data["_sd"] = append(data["_sd"].([]string), string(hash))
			}
			delete(data, field)
		}
		return nil
	}

	// Need to traverse deeper
	if arrayIndex >= 0 {
		arr, ok := value.([]any)
		if !ok {
			return fmt.Errorf("field %s is not an array", field)
		}
		if arrayIndex >= len(arr) {
			return fmt.Errorf("array index %d out of bounds for field %s", arrayIndex, field)
		}
		nextMap, ok := arr[arrayIndex].(map[string]any)
		if !ok {
			return fmt.Errorf("array element at index %d of field %s is not an object", arrayIndex, field)
		}
		if err := processPath(nextMap, pathParts[1:], disclosures); err != nil {
			return err
		}
		arr[arrayIndex] = nextMap
		data[field] = arr
		return nil
	}

	nextMap, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("field %s is not an object", field)
	}
	return processPath(nextMap, pathParts[1:], disclosures)
}

// VerifyVerifiableCredential verifies an SD-JWT credential and returns the disclosed claims
func VerifyVerifiableCredential(sdJwtStr string, key jwk.Key) (*credential.VerifiableCredential, error) {
	// Parse and verify the SD-JWT
	sdJwt, err := sdjwt.New(sdJwtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	// Get disclosed claims
	claims, err := sdJwt.GetDisclosedClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	// Convert claims back to VerifiableCredential
	vcBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	var vc credential.VerifiableCredential
	if err = json.Unmarshal(vcBytes, &vc); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VC: %w", err)
	}

	// Extract signature from SD-JWT
	parts := strings.Split(sdJwtStr, "~")
	if len(parts) < 1 {
		return nil, errors.New("invalid SD-JWT format")
	}

	jwsParts := strings.Split(parts[0], ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	if _, err = jws.Verify([]byte(parts[0]), jws.WithKey(key.Algorithm(), key)); err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	return &vc, nil
}

// SignVerifiablePresentation creates an SD-JWT from a VerifiablePresentation, making specified fields
// selectively disclosable according to the provided paths.
func SignVerifiablePresentation(vp credential.VerifiablePresentation, disclosurePaths []DisclosurePath, key jwk.Key) (*string, error) {
	if vp.IsEmpty() {
		return nil, errors.New("VerifiablePresentation is empty")
	}
	if key.KeyID() == "" {
		return nil, errors.New("key ID is required")
	}
	if key.Algorithm().String() == "" {
		return nil, errors.New("key algorithm is required")
	}

	// Convert VP to a map for manipulation
	vpMap, err := vp.ToMap()
	if err != nil {
		return nil, fmt.Errorf("failed to convert VP to map: %w", err)
	}

	// Add standard claims
	if vp.ID != "" {
		vpMap["jti"] = vp.ID
	}
	if !vp.Holder.IsEmpty() {
		vpMap["iss"] = vp.Holder.ID()
	}

	// Process disclosures
	disclosures := make([]disclosure.Disclosure, 0, len(disclosurePaths))
	processedMap, err := processDisclosures(vpMap, disclosurePaths, &disclosures)
	if err != nil {
		return nil, fmt.Errorf("failed to process disclosures: %w", err)
	}
	vpMap = processedMap

	// Marshal the claims to JSON
	payload, err := json.Marshal(vpMap)
	if err != nil {
		return nil, err
	}

	// Add protected header values
	jwsHeaders := jws.NewHeaders()
	headers := map[string]string{
		"typ": VPSDJWTType,
		"cty": credential.VPContentType,
		"alg": key.Algorithm().String(),
		"kid": key.KeyID(),
	}
	for k, v := range headers {
		if err = jwsHeaders.Set(k, v); err != nil {
			return nil, err
		}
	}

	// Sign the JWS with the holder's key
	signed, err := jws.Sign(payload, jws.WithKey(key.Algorithm(), key, jws.WithProtectedHeaders(jwsHeaders)))
	if err != nil {
		return nil, err
	}

	// Combine JWT with disclosures
	sdJWTParts := []string{(string)(signed)}
	for _, d := range disclosures {
		sdJWTParts = append(sdJWTParts, d.EncodedValue)
	}

	sdJwt := fmt.Sprintf("%s~", strings.Join(sdJWTParts, "~"))
	return &sdJwt, nil
}

// VerifyVerifiablePresentation verifies an SD-JWT presentation and returns the disclosed claims
func VerifyVerifiablePresentation(sdJwtStr string, key jwk.Key) (*credential.VerifiablePresentation, error) {
	// Parse and verify the SD-JWT
	sdJwt, err := sdjwt.New(sdJwtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SD-JWT: %w", err)
	}

	// Get disclosed claims
	claims, err := sdJwt.GetDisclosedClaims()
	if err != nil {
		return nil, fmt.Errorf("failed to get disclosed claims: %w", err)
	}

	// Convert claims back to VerifiablePresentation
	vpBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	var vp credential.VerifiablePresentation
	if err = json.Unmarshal(vpBytes, &vp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VP: %w", err)
	}

	// Extract signature from SD-JWT
	parts := strings.Split(sdJwtStr, "~")
	if len(parts) < 1 {
		return nil, errors.New("invalid SD-JWT format")
	}

	jwsParts := strings.Split(parts[0], ".")
	if len(jwsParts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	if _, err = jws.Verify([]byte(parts[0]), jws.WithKey(key.Algorithm(), key)); err != nil {
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	return &vp, nil
}
