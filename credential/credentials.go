package credential

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/TBD54566975/vc-jose-cose-go/util"
)

const (
	VerifiableCredentialsLinkedDataContext               string = "https://www.w3.org/ns/credentials/v2"
	VerifiableCredentialsUndefinedTermsLinkedDataContext string = "https://www.w3.org/ns/credentials/undefined-terms/v2"
	VerifiableCredentialType                             string = "VerifiableCredential"
	VerifiablePresentationType                           string = "VerifiablePresentation"
	EnvelopedVerifiableCredentialType                    string = "EnvelopedVerifiableCredential"
	EnvelopedVerifiablePresentationType                  string = "EnvelopedVerifiablePresentation"

	VerifiableCredentialJSONSchemaType string = "JsonSchema"
	VerifiableCredentialIDProperty     string = "id"
)

// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
type VerifiableCredential struct {
	Context SingleOrArray[string] `json:"@context" validate:"required"`
	ID      string                `json:"id,omitempty"`
	Type    SingleOrArray[string] `json:"type" validate:"required"`
	// either a URI or an object containing an `id` property.
	Issuer IssuerHolder `json:"issuer,omitempty" validate:"required"`
	// https://www.w3.org/TR/xmlschema11-2/#dateTimes
	ValidFrom        string             `json:"validFrom,omitempty" validate:"required"`
	ValidUntil       string             `json:"validUntil,omitempty"`
	CredentialStatus SingleOrArray[any] `json:"credentialStatus,omitempty" validate:"omitempty"`
	// This is where the subject's ID *may* be present
	CredentialSubject CredentialSubject               `json:"credentialSubject" validate:"required"`
	CredentialSchema  SingleOrArray[CredentialSchema] `json:"credentialSchema,omitempty" validate:"omitempty"`
	TermsOfUse        SingleOrArray[any]              `json:"termsOfUse,omitempty" validate:"omitempty,dive"`
	Evidence          SingleOrArray[any]              `json:"evidence,omitempty" validate:"omitempty"`
}

// IssuerHolder represents the issuer of a Verifiable Credential or holder of a Verifiable Presentation, which can be
// either a URL string or an object containing an ID property
type IssuerHolder struct {
	id     string
	object map[string]any
}

// UnmarshalJSON implements the json.Unmarshaler interface for IssuerHolder
func (i *IssuerHolder) UnmarshalJSON(data []byte) error {
	// First, try to unmarshal as a string (URL)
	var urlString string
	if err := json.Unmarshal(data, &urlString); err == nil {
		i.id = urlString
		i.object = nil
		return nil
	}

	// If that fails, try to unmarshal as an object
	obj := make(map[string]any)
	if err := json.Unmarshal(data, &obj); err == nil {
		id, ok := obj["id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("issuer object must contain an 'id' property of type string")
		}
		i.id = id
		i.object = obj
		return nil
	}

	return fmt.Errorf("issuer must be either a URL string or an object with an 'id' property")
}

// MarshalJSON implements the json.Marshaler interface for IssuerHolder
func (i *IssuerHolder) MarshalJSON() ([]byte, error) {
	if i.object != nil {
		return json.Marshal(i.object)
	}
	return json.Marshal(i.id)
}

// ID returns the ID of the issuer/holder
func (i *IssuerHolder) ID() string {
	return i.id
}

// IsObject returns true if the issuer is an object, false if it's a string
func (i *IssuerHolder) IsObject() bool {
	return i.object != nil
}

// Get returns the value of a property in the issuer/holder object, or nil if the issuer/holder is a string
// or the property doesn't exist
func (i *IssuerHolder) Get(property string) interface{} {
	if i.object == nil {
		return nil
	}
	return i.object[property]
}

// CredentialSubject represents the subject of a Verifiable Credential
type CredentialSubject map[string]any

func (cs CredentialSubject) GetID() string {
	id := ""
	if gotID, ok := cs[VerifiableCredentialIDProperty]; ok {
		id = gotID.(string)
	}
	return id
}

type CredentialSchema struct {
	ID        string `json:"id" validate:"required"`
	Type      string `json:"type" validate:"required"`
	DigestSRI string `json:"digestSRI,omitempty"`
}

func (v *VerifiableCredential) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiableCredential{})
}

func (v *VerifiableCredential) IsValid() error {
	return util.NewValidator().Struct(v)
}

func (v *VerifiableCredential) IssuerID() string {
	return v.Issuer.ID()
}

// VerifiablePresentation https://www.w3.org/TR/vc-data-model-2.0/#verifiable-presentations
type VerifiablePresentation struct {
	Context              SingleOrArray[string]  `json:"@context,omitempty"`
	ID                   string                 `json:"id,omitempty"`
	Holder               IssuerHolder           `json:"holder,omitempty"`
	Type                 SingleOrArray[string]  `json:"type" validate:"required"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty"`
}

func (v *VerifiablePresentation) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiablePresentation{})
}

func (v *VerifiablePresentation) IsValid() error {
	return util.NewValidator().Struct(v)
}
