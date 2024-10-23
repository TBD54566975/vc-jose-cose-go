package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/x25519"
)

type (
	Proof              any
	KeyType            string
	HashType           string
	SignatureAlgorithm string
)

const (
	Ed25519        KeyType = "Ed25519"
	X25519         KeyType = "X25519"
	SECP256k1      KeyType = "secp256k1"
	SECP256k1ECDSA KeyType = "secp256k1-ECDSA"
	P224           KeyType = "P-224"
	P256           KeyType = "P-256"
	P384           KeyType = "P-384"
	P521           KeyType = "P-521"
)

func GenerateJWKWithAlgorithm(eca jwa.EllipticCurveAlgorithm) (jwk.Key, error) {
	// Generate the key pair
	_, privKey, err := GenerateKeyByEllipticCurveAlgorithm(eca)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Convert the private key to JWK
	jwkKey, err := jwk.FromRaw(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	// Set the algorithm based on the elliptic curve algorithm
	var alg jwa.SignatureAlgorithm
	switch eca {
	case jwa.P256:
		alg = jwa.ES256
	case jwa.P384:
		alg = jwa.ES384
	case jwa.P521:
		alg = jwa.ES512
	case jwa.Ed25519:
		alg = jwa.EdDSA
	default:
		return nil, fmt.Errorf("unsupported elliptic curve algorithm: %s", eca)
	}

	thumbprintBytes, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thumbprint: %w", err)
	}
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)
	if err = jwkKey.Set(jwk.KeyIDKey, thumbprint); err != nil {
		return nil, fmt.Errorf("failed to set key ID in JWK: %w", err)
	}
	// Set the algorithm in the JWK
	if err = jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("failed to set algorithm in JWK: %w", err)
	}

	return jwkKey, nil
}

// GenerateKeyByEllipticCurveAlgorithm creates a brand-new key, returning the public and private key for the given elliptic curve algorithm
func GenerateKeyByEllipticCurveAlgorithm(eca jwa.EllipticCurveAlgorithm) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch eca {
	case jwa.Ed25519:
		return GenerateEd25519Key()
	case jwa.X25519:
		return GenerateX25519Key()
	case jwa.P256:
		return GenerateP256Key()
	case jwa.P384:
		return GenerateP384Key()
	case jwa.P521:
		return GenerateP521Key()
	}
	return nil, nil, fmt.Errorf("unsupported elliptic curve algorithm: %s", eca)
}

// GenerateKeyByKeyType creates a brand-new key, returning the public and private key for the given key type
func GenerateKeyByKeyType(kt KeyType) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch kt {
	case Ed25519:
		return GenerateEd25519Key()
	case X25519:
		return GenerateX25519Key()
	case SECP256k1:
		return GenerateSECP256k1Key()
	case SECP256k1ECDSA:
		secpPub, secpPriv, err := GenerateSECP256k1Key()
		if err == nil {
			ecdsaPub := secpPub.ToECDSA()
			ecdsaPriv := secpPriv.ToECDSA()
			return *ecdsaPub, *ecdsaPriv, nil
		}
		return nil, nil, err
	case P224:
		return GenerateP224Key()
	case P256:
		return GenerateP256Key()
	case P384:
		return GenerateP384Key()
	case P521:
		return GenerateP521Key()
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kt)
}

type Option int

const (
	ECDSAMarshalCompressed Option = iota
	ECDSAUnmarshalCompressed
)

// PubKeyToBytes constructs a byte representation of a public key, for a set number of supported key types
func PubKeyToBytes(key crypto.PublicKey, opts ...Option) ([]byte, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PublicKey)
	}

	switch k := key.(type) {
	case ed25519.PublicKey:
		return k, nil
	case x25519.PublicKey:
		return k, nil
	case secp.PublicKey:
		return k.SerializeCompressed(), nil
	case ecdsa.PublicKey:
		if k.Curve == btcec.S256() {
			x := new(btcec.FieldVal)
			x.SetByteSlice(k.X.Bytes())
			y := new(btcec.FieldVal)
			y.SetByteSlice(k.Y.Bytes())
			return btcec.NewPublicKey(x, y).SerializeCompressed(), nil
		}

		// check if we should marshal the key in compressed form
		if len(opts) == 1 && opts[0] == ECDSAMarshalCompressed {
			return elliptic.MarshalCompressed(k.Curve, k.X, k.Y), nil
		}

		// go from ecdsa public key to bytes
		pk, err := x509.MarshalPKIXPublicKey(&k)
		if err != nil {
			return nil, err
		}
		return pk, nil
	case rsa.PublicKey:
		return x509.MarshalPKCS1PublicKey(&k), nil
	}

	return nil, errors.New("unknown public key type; could not convert to bytes")
}

// BytesToPubKey reconstructs a public key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PubKeyToBytes`
func BytesToPubKey(keyBytes []byte, kt KeyType, opts ...Option) (crypto.PublicKey, error) {
	switch kt {
	case Ed25519:
		return ed25519.PublicKey(keyBytes), nil
	case X25519:
		return x25519.PublicKey(keyBytes), nil
	case SECP256k1:
		pubKey, err := secp.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pubKey, nil
	case SECP256k1ECDSA:
		pk, err := secp.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pk.ToECDSA(), nil
	case P224, P256, P384, P521:
		// check if we should unmarshal the key in compressed form
		if len(opts) == 1 && opts[0] == ECDSAUnmarshalCompressed {
			switch kt {
			case P224:
				x, y := elliptic.UnmarshalCompressed(elliptic.P224(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P224(), X: x, Y: y}, nil
			case P256:
				x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
			case P384:
				x, y := elliptic.UnmarshalCompressed(elliptic.P384(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
			case P521:
				x, y := elliptic.UnmarshalCompressed(elliptic.P521(), keyBytes)
				return ecdsa.PublicKey{Curve: elliptic.P521(), X: x, Y: y}, nil
			}
		}

		key, err := x509.ParsePKIXPublicKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *key.(*ecdsa.PublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

// GetKeyTypeFromPrivateKey returns the key type for a private key for known key types
func GetKeyTypeFromPrivateKey(key crypto.PrivateKey) (KeyType, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PrivateKey)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return Ed25519, nil
	case x25519.PrivateKey:
		return X25519, nil
	case secp.PrivateKey:
		return SECP256k1, nil
	case ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P224():
			return P224, nil
		case elliptic.P256():
			return P256, nil
		case elliptic.P384():
			return P384, nil
		case elliptic.P521():
			return P521, nil
		case btcec.S256():
			return SECP256k1ECDSA, nil
		default:
			return "", fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
	default:
		return "", errors.New("unknown private key type")
	}
}

// PrivKeyToBytes constructs a byte representation of a private key, for a set number of supported key types
func PrivKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(crypto.PrivateKey)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, nil
	case x25519.PrivateKey:
		return k, nil
	case secp.PrivateKey:
		return k.Serialize(), nil
	case ecdsa.PrivateKey:
		if k.Curve == btcec.S256() {
			scalar := new(btcec.ModNScalar)
			_ = scalar.SetByteSlice(k.D.Bytes())
			privKey := secp.NewPrivateKey(scalar)
			return privKey.Serialize(), nil
		}
		return x509.MarshalECPrivateKey(&k)
	default:
		return nil, errors.New("unknown private key type; could not convert to bytes")
	}
}

// BytesToPrivKey reconstructs a private key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PrivKeyToBytes`
func BytesToPrivKey(keyBytes []byte, kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case Ed25519:
		return ed25519.PrivateKey(keyBytes), nil
	case X25519:
		return x25519.PrivateKey(keyBytes), nil
	case SECP256k1:
		return *secp.PrivKeyFromBytes(keyBytes), nil
	case SECP256k1ECDSA:
		privKey, _ := btcec.PrivKeyFromBytes(keyBytes)
		return *privKey.ToECDSA(), nil
	case P224, P256, P384, P521:
		privKey, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *privKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

// SECP256k1ECDSAPubKeyToSECP256k1 converts an ecdsa.PublicKey to a secp.PublicKey
func SECP256k1ECDSAPubKeyToSECP256k1(key ecdsa.PublicKey) secp.PublicKey {
	x := new(btcec.FieldVal)
	x.SetByteSlice(key.X.Bytes())
	y := new(btcec.FieldVal)
	y.SetByteSlice(key.Y.Bytes())
	return *btcec.NewPublicKey(x, y)
}

// SECP256k1ECDSASPrivKeyToSECP256k1 converts an ecdsa.PrivateKey to a secp.PrivateKey
func SECP256k1ECDSASPrivKeyToSECP256k1(key ecdsa.PrivateKey) secp.PrivateKey {
	scalar := new(btcec.ModNScalar)
	scalar.SetByteSlice(key.D.Bytes())
	return *secp.NewPrivateKey(scalar)
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateX25519Key() (x25519.PublicKey, x25519.PrivateKey, error) {
	return x25519.GenerateKey(rand.Reader)
}

func GenerateSECP256k1Key() (secp.PublicKey, secp.PrivateKey, error) {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return secp.PublicKey{}, secp.PrivateKey{}, err
	}
	pubKey := privKey.PubKey()
	return *pubKey, *privKey, nil
}

func GenerateP224Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P224())
}

func GenerateP256Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P256())
}

func GenerateP384Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P384())
}

func GenerateP521Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P521())
}

func generateECDSAKey(curve elliptic.Curve) (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ecdsa.PublicKey{}, ecdsa.PrivateKey{}, err
	}
	return privKey.PublicKey, *privKey, nil
}

func (kt KeyType) String() string {
	return string(kt)
}

// IsSupportedKeyType returns true if the key type is supported
func IsSupportedKeyType(kt KeyType) bool {
	supported := GetSupportedKeyTypes()
	for _, t := range supported {
		if kt == t {
			return true
		}
	}
	return false
}

// GetSupportedJWKKeyTypes returns a list of supported JWK key types
// RSA, secp256k1, and P-224 are not supported by the lib we use for JWK
func GetSupportedJWKKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, SECP256k1, SECP256k1ECDSA, P256, P384, P521}
}

// GetSupportedKeyTypes returns a list of supported key types
func GetSupportedKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, SECP256k1, SECP256k1ECDSA, P224, P256, P384, P521}
}
