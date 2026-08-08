package adminapi

import "testing"

func TestIsAdminRole(t *testing.T) {
	cases := []struct {
		role string
		want bool
	}{
		{"admin", true},
		{"superadmin", true},
		{"org_admin", false},
		{"analyst", false},
		{"viewer", false},
		{"", false},
		{"ADMIN", false}, // spider-snoop's role claim is lowercase; no case-folding here
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			if got := isAdminRole(c.role); got != c.want {
				t.Fatalf("isAdminRole(%q) = %v, want %v", c.role, got, c.want)
			}
		})
	}
}
