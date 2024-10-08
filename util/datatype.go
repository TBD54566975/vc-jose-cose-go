package util

import (
	"fmt"

	"github.com/goccy/go-json"
)

// SingleOrArray represents a value that can be either a single item or an array of items
type SingleOrArray[T any] []T

// UnmarshalJSON implements custom unmarshaling for SingleOrArray
func (sa *SingleOrArray[T]) UnmarshalJSON(data []byte) error {
	var single T
	if err := json.Unmarshal(data, &single); err == nil {
		*sa = SingleOrArray[T]{single}
		return nil
	}

	var multiple []T
	if err := json.Unmarshal(data, &multiple); err == nil {
		*sa = multiple
		return nil
	}

	return fmt.Errorf("invalid format for SingleOrArray")
}

// MarshalJSON implements custom marshaling for SingleOrArray
func (sa SingleOrArray[T]) MarshalJSON() ([]byte, error) {
	if len(sa) == 1 {
		return json.Marshal((sa)[0])
	}
	return json.Marshal([]T(sa))
}
