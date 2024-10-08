package controller

import (
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/TBD54566975/vc-jose-cose-go/util"
)

const (
	TypeJsonWebKey string = "JsonWebKey"
	TypeMultikey   string = "Multikey"
)

// Document data model as per https://www.w3.org/TR/controller-document/#data-model
type Document struct {
	ID                   string                     `json:"id" validate:"required"`
	AlsoKnownAs          []string                   `json:"alsoKnownAs,omitempty"`
	Controller           util.SingleOrArray[string] `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod       `json:"verificationMethod,omitempty"`
	Authentication       []VerificationMethodMap    `json:"authentication,omitempty"`
	AssertionMethod      []VerificationMethodMap    `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationMethodMap    `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationMethodMap    `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationMethodMap    `json:"capabilityDelegation,omitempty"`
}

type VerificationMethod struct {
	ID                 string  `json:"id" validate:"required"`
	Type               string  `json:"type" validate:"required"`
	Controller         string  `json:"controller" validate:"required"`
	Revoked            string  `json:"revoked,omitempty"`
	PublicKeyJWK       jwk.Key `json:"publicKeyJwk,omitempty"`
	SecretKeyJWK       jwk.Key `json:"secretKeyJwk,omitempty"`
	PublicKeyMultibase string  `json:"publicKeyMultibase,omitempty"`
	SecretKeyMultibase string  `json:"secretKeyMultibase,omitempty"`
}

type VerificationMethodMap struct {
}
