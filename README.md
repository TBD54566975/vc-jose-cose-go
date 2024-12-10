[![godoc vc-jose-cose-go](https://img.shields.io/badge/godoc-vc--jose--cose--go-blue)](https://pkg.go.dev/github.com/decentralgabe/vc-jose-cose-go)
[![go version 1.23.3](https://img.shields.io/badge/go_version-1.23.2-brightgreen)](https://golang.org/)
[![Go Report Card](https://goreportcard.com/badge/github.com/decentralgabe/vc-jose-cose-go)](https://goreportcard.com/report/github.com/decentralgabe/vc-jose-cose-go)
[![license Apache 2](https://img.shields.io/badge/license-Apache%202-black)](https://github.com/decentralgabe/vc-jose-cose-go/blob/main/LICENSE)
[![issues](https://img.shields.io/github/issues/decentralgabe/vc-jose-cose-go)](https://github.com/decentralgabe/vc-jose-cose-go/issues)
![ci status](https://github.com/decentralgabe/vc-jose-cose-go/actions/workflows/ci.yml/badge.svg?branch=main&event=push)
[![codecov](https://codecov.io/github/decentralgabe/vm-jose-cose-go/graph/badge.svg?token=PIS07W0RQJ)](https://codecov.io/github/decentralgabe/vc-jose-cose-go)

# VC JOSE COSE in go

A lightweight go implementation of the [W3C Verifiable Credentials v2 Data Model](https://www.w3.org/TR/vm-data-model-2.0)
with support for [Securing Verifiable Credentials using JOSE and COSE](https://www.w3.org/TR/vm-jose-cose/).

## Usage

This library provides Go implementations for signing and verifying Verifiable Credentials (VCs) and Verifiable Presentations (VPs) using JOSE, SD-JWT, and COSE formats.

## Installation

```
go get github.com/decentralgabe/vc-jose-cose-go
```

### JOSE (JSON Object Signing and Encryption)

```go
import (
    "github.com/decentralgabe/vc-jose-cose-go/jose"
    "github.com/decentralgabe/vc-jose-cose-go/credential"
    "github.com/decentralgabe/vc-jose-cose-go/util"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwa"
)

func main() {
    // Create a VC
    vm := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		},
	}

    // Create the issuer's key
    key, _ := util.GenerateJWK(jwa.Ed25519)

    // Sign the VC
    jwt, err := jose.SignVerifiableCredential(vm, key)
    if err != nil {
        // Handle error
    }
    
    vm, err := jose.VerifyVerifiableCredential(jwt, key)
    if err != nil {
        // Handle error
    }
    // Use the verified VC
}
```

### SD-JWT (Selective Disclosure JWT)

```go
    import (
        "github.com/decentralgabe/vc-jose-cose-go/sdjwt"
        "github.com/decentralgabe/vc-jose-cose-go/credential"
        "github.com/decentralgabe/vc-jose-cose-go/util"
        "github.com/lestrrat-go/jwx/v2/jwk"
        "github.com/lestrrat-go/jwx/v2/jwa"
    )

    func main() {
        vm := credential.VerifiableCredential{
            Context:   []string{"https://www.w3.org/2018/credentials/v1"},
            ID:        "https://example.edu/credentials/1872",
            Type:      []string{"VerifiableCredential"},
            Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
            ValidFrom: "2010-01-01T19:23:24Z",
            CredentialSubject: map[string]any{
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
            },
	    }

        // Define disclosure paths
        disclosurePaths := []sdjwt.DisclosurePath{
            "issuer",
            "credentialSubject.id",
        }

        // Create the issuer's key
        key, _ := util.GenerateJWK(jwa.Ed25519)

        // Create SD-JWT
        sdJWT, err := sdjwt.SignVerifiableCredential(vm, disclosurePaths, issuerKey)
        if err != nil {
            // Handle error
        }

   		verifiedVC, err := sdjwt.VerifyVerifiableCredential(*sdJWT, issuerKey)
        if err != nil {
            // Handle error
        }
    }
```

### COSE (CBOR Object Signing and Encryption)

```go
import (
    "github.com/decentralgabe/vc-jose-cose-go/cose"
    "github.com/decentralgabe/vc-jose-cose-go/credential"
    "github.com/decentralgabe/vc-jose-cose-go/util"
    "github.com/lestrrat-go/jwx/v2/jwk"
    "github.com/lestrrat-go/jwx/v2/jwa"
)

func main() {
    // Create a VC
    vm := credential.VerifiableCredential{
		Context:   []string{"https://www.w3.org/2018/credentials/v1"},
		ID:        "https://example.edu/credentials/1872",
		Type:      []string{"VerifiableCredential"},
		Issuer:    credential.NewIssuerHolderFromString("did:example:issuer"),
		ValidFrom: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		},
	}

    // Create the issuer's key
    key, _ := util.GenerateJWK(jwa.Ed25519)

    // Sign the VC
    cs1, err := cose.SignVerifiableCredential(vm, key)
    if err != nil {
        // Handle error
    }
    
    vm, err := cose.VerifyVerifiableCredential(cs1, key)
    if err != nil {
        // Handle error
    }
    // Use the verified VC
}
```