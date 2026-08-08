// Package adminapi is the gateway's HTTP admin API (issue #13, Phase 4):
// agent, group, and policy management over HTTP, mounted at /admin/.
//
// Trust is two independently-verified checks, not a new login system.
// (1) A service-to-service NHI bearer token, minted via the exact same
// /token client_credentials grant every other agent already uses,
// scoped to authserver.AdminResource -- a reserved audience only a
// config-designated allowlist of agents may mint (see
// AuthServer.ValidateAdminAccessToken). This proves the caller really is
// the one trusted integration backend (spider-snoop's own backend, in
// the shipped deployment). (2) A live introspection call against that
// backend's own already-existing session-validation endpoint
// (SpiderSnoopIntrospector), proving the specific human behind the
// request currently holds an admin/superadmin role right now. Both must
// pass -- see Gate. Neither check requires spider-snoop to change: its
// login, session, and role model are untouched.
package adminapi
