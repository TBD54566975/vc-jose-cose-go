package credential

import (
	"encoding/json"
	"fmt"
)

// SingleOrArray is a generic type that can represent either a single value or an array of values
type SingleOrArray[T any] struct {
	value any
}

// UnmarshalJSON implements the json.Unmarshaler interface for SingleOrArray
func (sa *SingleOrArray[T]) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	switch value := v.(type) {
	case T:
		sa.value = value
	case []T:
		sa.value = value
	case []any:
		// Convert []any to []T
		typedSlice := make([]T, 0, len(value))
		for _, item := range value {
			if typedItem, ok := item.(T); ok {
				typedSlice = append(typedSlice, typedItem)
			} else {
				return fmt.Errorf("invalid type in array: %T", item)
			}
		}
		sa.value = typedSlice
	default:
		return fmt.Errorf("invalid type: %T", v)
	}

	return nil
}

// MarshalJSON implements the json.Marshaler interface for SingleOrArray
func (sa *SingleOrArray[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(sa.value)
}

// Get returns the underlying value (either T or []T)
func (sa *SingleOrArray[T]) Get() any {
	return sa.value
}
