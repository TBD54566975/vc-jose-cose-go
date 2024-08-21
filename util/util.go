package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/go-playground/validator/v10"
)

func NewValidator() *validator.Validate {
	return validator.New()
}

func IsValidStruct(data any) error {
	if t := reflect.TypeOf(data).Kind(); t != reflect.Struct {
		return fmt.Errorf("provided data is not of Kind struct: %+v", data)
	}
	return NewValidator().Struct(data)
}

// Copy makes a 1:1 copy of src into dst.
func Copy(src any, dst any) error {
	if err := validateCopy(src, dst); err != nil {
		return err
	}
	bytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(bytes, dst)
}

func validateCopy(src any, dst any) error {
	if src == nil {
		return errors.New("src is nil")
	}
	if dst == nil {
		return errors.New("dst is nil")
	}

	// Type check
	srcType := reflect.TypeOf(src)
	dstType := reflect.TypeOf(dst)
	if srcType != dstType {
		return errors.New("type of src and dst must match")
	}

	// Kind checks
	srcKind := srcType.Kind()
	if !(srcKind == reflect.Ptr || srcKind == reflect.Slice) {
		return errors.New("src is not of kind ptr or slice")
	}
	dstKind := dstType.Kind()
	if !(dstKind == reflect.Ptr || dstKind == reflect.Slice) {
		return errors.New("dst is not of kind ptr or slice")
	}
	return nil
}

func Contains(needle string, haystack []string) bool {
	for _, maybe := range haystack {
		if maybe == needle {
			return true
		}
	}
	return false
}

// PrettyJSON JSON-ifies data in a 'pretty-print' fashion
func PrettyJSON(data any) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}
