package adminapi

// isAdminRole reports whether role grants gateway admin API access --
// mirrors spider-snoop's own platform-admin bypass semantics in
// require_role (app/utils/auth.py): SUPERADMIN and the legacy ADMIN
// alias always pass every role check regardless of what's required;
// ORG_ADMIN (org-scoped, not platform-wide) and every lower role do not.
// A pure, directly-testable function -- no I/O, no dependency on the
// live introspection call itself.
func isAdminRole(role string) bool {
	switch role {
	case "admin", "superadmin":
		return true
	default:
		return false
	}
}
