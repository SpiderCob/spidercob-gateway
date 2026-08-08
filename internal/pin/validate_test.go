package pin

import (
	"testing"
)

func TestValidateArguments_ValidArgumentsPass(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)
	args := []byte(`{"query":"open tickets"}`)
	if err := ValidateArguments(schema, args); err != nil {
		t.Fatalf("ValidateArguments: %v, want nil", err)
	}
}

func TestValidateArguments_MissingRequiredFieldFails(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}`)
	args := []byte(`{}`)
	if err := ValidateArguments(schema, args); err == nil {
		t.Fatal("ValidateArguments with a missing required field: got nil error, want non-nil")
	}
}

func TestValidateArguments_WrongTypeFails(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"limit":{"type":"integer"}}}`)
	args := []byte(`{"limit":"not a number"}`)
	if err := ValidateArguments(schema, args); err == nil {
		t.Fatal("ValidateArguments with a wrong-typed field: got nil error, want non-nil")
	}
}

func TestValidateArguments_RespectsAdditionalPropertiesFalse(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"}},"additionalProperties":false}`)
	args := []byte(`{"query":"ok","unexpected_field":"nope"}`)
	if err := ValidateArguments(schema, args); err == nil {
		t.Fatal("ValidateArguments with an unexpected field under additionalProperties:false: got nil error, want non-nil")
	}
}

func TestValidateArguments_AdditionalPropertiesAllowedByDefault(t *testing.T) {
	// additionalProperties defaults to allowed under JSON Schema -- the
	// gateway must not impose a stricter default than the schema itself
	// declares.
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"}}}`)
	args := []byte(`{"query":"ok","extra":"fine"}`)
	if err := ValidateArguments(schema, args); err != nil {
		t.Fatalf("ValidateArguments: %v, want nil (additionalProperties unset means allowed)", err)
	}
}

func TestValidateArguments_EmptySchemaAllowsAnything(t *testing.T) {
	// No inputSchema was ever pinned for this tool -- nothing to validate
	// against, so any arguments must pass (story 23).
	if err := ValidateArguments(nil, []byte(`{"anything":"goes","here":123}`)); err != nil {
		t.Fatalf("ValidateArguments with a nil schema: %v, want nil", err)
	}
	if err := ValidateArguments([]byte(``), []byte(`{"anything":"goes"}`)); err != nil {
		t.Fatalf("ValidateArguments with an empty schema: %v, want nil", err)
	}
}

func TestValidateArguments_EmptyArgumentsTreatedAsEmptyObject(t *testing.T) {
	schema := []byte(`{"type":"object","properties":{"query":{"type":"string"}}}`)
	if err := ValidateArguments(schema, nil); err != nil {
		t.Fatalf("ValidateArguments with nil arguments against a schema with no required fields: %v, want nil", err)
	}
}

func TestValidateArguments_MalformedSchemaErrors(t *testing.T) {
	if err := ValidateArguments([]byte(`{not valid json`), []byte(`{}`)); err == nil {
		t.Fatal("ValidateArguments with malformed schema JSON: got nil error, want non-nil")
	}
}

func TestValidateArguments_MalformedArgumentsErrors(t *testing.T) {
	schema := []byte(`{"type":"object"}`)
	if err := ValidateArguments(schema, []byte(`{not valid json`)); err == nil {
		t.Fatal("ValidateArguments with malformed arguments JSON: got nil error, want non-nil")
	}
}
