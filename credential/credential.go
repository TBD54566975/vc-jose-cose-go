package credential

import (
	"fmt"
	"reflect"

	"github.com/goccy/go-json"

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

	VCContentType string = "vc"
	VPContentType string = "vp"
)

// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/vc-data-model-2.0/#verifiable-credentials
type VerifiableCredential struct {
	Context util.SingleOrArray[string] `json:"@context,omitempty" validate:"required"`
	Type    util.SingleOrArray[string] `json:"type,omitempty" validate:"required"`
	ID      string                     `json:"id,omitempty"`
	// either a URI or an object containing an `id` property.
	Issuer *IssuerHolder `json:"issuer,omitempty" validate:"required"`
	// https://www.w3.org/TR/xmlschema11-2/#dateTimes
	ValidFrom  string `json:"validFrom,omitempty" validate:"required"`
	ValidUntil string `json:"validUntil,omitempty"`
	// This is where the subject's ID *may* be present
	CredentialSubject Subject                    `json:"credentialSubject,omitempty"`
	CredentialSchema  util.SingleOrArray[Schema] `json:"credentialSchema,omitempty"`
	CredentialStatus  util.SingleOrArray[any]    `json:"credentialStatus,omitempty"`
	TermsOfUse        util.SingleOrArray[any]    `json:"termsOfUse,omitempty"`
	Evidence          util.SingleOrArray[any]    `json:"evidence,omitempty"`
}

// ToMap converts the VerifiableCredential to a map[string]any
func (vc *VerifiableCredential) ToMap() (map[string]any, error) {
	jsonBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VerifiableCredential: %w", err)
	}

	var result map[string]any
	if err = json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiableCredential to map: %w", err)
	}

	return result, nil
}

// IssuerHolder represents the issuer of a Verifiable Credential or holder of a Verifiable Presentation, which can be
// either a URL string or an object containing an ID property
type IssuerHolder struct {
	id     string
	object map[string]any
}

// UnmarshalJSON implements custom unmarshaling for IssuerHolder
func (i *IssuerHolder) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as a string
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		i.id = str
		i.object = nil
		return nil
	}

	// If not a string, try to unmarshal as an object
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err == nil {
		id, ok := obj["id"].(string)
		if !ok {
			return fmt.Errorf("issuer object must contain an 'id' property of type string")
		}
		i.id = id
		i.object = obj
		return nil
	}

	return fmt.Errorf("invalid format for IssuerHolder: must be a string or an object with an 'id' property")
}

// NewIssuerHolderFromString creates an IssuerHolder from a string (URL or ID)
func NewIssuerHolderFromString(id string) *IssuerHolder {
	return &IssuerHolder{id: id}
}

// NewIssuerHolderFromObject creates an IssuerHolder from an object with an `id` field
func NewIssuerHolderFromObject(id string, object map[string]any) *IssuerHolder {
	return &IssuerHolder{id: id, object: object}
}

// MarshalJSON implements custom marshaling for IssuerHolder
func (i *IssuerHolder) MarshalJSON() ([]byte, error) {
	if i.object != nil {
		return json.Marshal(i.object)
	}
	return json.Marshal(i.id)
}

// ID returns the ID of the issuer
func (i *IssuerHolder) ID() string {
	return i.id
}

// IsObject returns true if the issuer is an object, false if it's a string
func (i *IssuerHolder) IsObject() bool {
	return i.object != nil
}

// IsEmpty returns true if the issuer is empty
func (i *IssuerHolder) IsEmpty() bool {
	return i.id == "" && i.object == nil
}

// Get returns the value of a property in the issuer/holder object, or nil if the issuer/holder is a string
// or the property doesn't exist
func (i *IssuerHolder) Get(property string) any {
	if i.object == nil {
		return nil
	}
	return i.object[property]
}

// Subject represents the subject of a Verifiable Credential
type Subject map[string]any

func (s Subject) GetID() string {
	id := ""
	if gotID, ok := s[VerifiableCredentialIDProperty]; ok {
		id = gotID.(string)
	}
	return id
}

type Schema struct {
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
	Context              util.SingleOrArray[string] `json:"@context,omitempty" validate:"required"`
	Type                 util.SingleOrArray[string] `json:"type,omitempty" validate:"required"`
	ID                   string                     `json:"id,omitempty"`
	Holder               *IssuerHolder              `json:"holder,omitempty"`
	VerifiableCredential []VerifiableCredential     `json:"verifiableCredential,omitempty"`
}

// ToMap converts the VerifiablePresentation to a map[string]any
func (vp *VerifiablePresentation) ToMap() (map[string]any, error) {
	jsonBytes, err := json.Marshal(vp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal VerifiablePresentation: %w", err)
	}

	var result map[string]any
	if err = json.Unmarshal(jsonBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal VerifiablePresentation to map: %w", err)
	}

	return result, nil
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
