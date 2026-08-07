package policy

import (
	"net/http/httptest"
	"testing"
)

func TestAllowAll_AlwaysAllows(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp/jira/", nil)
	if !(AllowAll{}).Allow("jira", r) {
		t.Fatal("AllowAll should always allow")
	}
}

func TestDenyAll_AlwaysDenies(t *testing.T) {
	r := httptest.NewRequest("POST", "/mcp/jira/", nil)
	if (DenyAll{}).Allow("jira", r) {
		t.Fatal("DenyAll should always deny")
	}
}
