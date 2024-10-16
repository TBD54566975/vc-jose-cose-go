package sdjwt

import (
	"errors"
	"fmt"

	sdjwt "github.com/MichaelFraser99/go-sd-jwt"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/TBD54566975/vc-jose-cose-go/credential"
	"github.com/TBD54566975/vc-jose-cose-go/jose"
)

const (
	VCSDJWTType = "vc+sd-jwt"
	VPSDJWTType = "vp+sd-jwt"
)

type DisclosedClaims map[string]any

// SignVerifiableCredential signs a VerifiableCredential using SD-JWT.
func SignVerifiableCredential(vc credential.VerifiableCredential, key jwk.Key) (*string, error) {
	if vc.IsEmpty() {
		return nil, errors.New("VerifiableCredential is empty")
	}

	jwt, err := jose.SignVerifiableCredential(vc, key)
	if err != nil || jwt == nil {
		return nil, fmt.Errorf("failed to sign JWT before generating SD-JWT: %w", err)
	}

	// Create SD-JWT from JWT
	sdJWT, err := sdjwt.New(*jwt)
	if err != nil {
		return nil, fmt.Errorf("failed to create SD-JWT from JWT: %w", err)
	}

	return sdJWT.Token()
}

// VerifyVerifiableCredential verifies a VerifiableCredential SD-JWT using the provided key.
func VerifyVerifiableCredential(sdJWT string, key jwk.Key) (*credential.VerifiableCredential, DisclosedClaims, error) {
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

	vc, err := jose.VerifyVerifiableCredential(*token, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify SD-JWT: %w", err)
	}

	return vc, disclosedClaims, nil
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
