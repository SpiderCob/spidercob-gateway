package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	_ "modernc.org/sqlite" // registers the "sqlite" driver, no cgo
)

// SQLiteStore is the Store implementation backing Mode A / NHI identity.
//
// Write-concurrency (MASTER_PLAN.md §7 open decision, resolved 2026-08-07):
// modernc.org/sqlite is a single-writer engine, and Go's database/sql pool
// will happily hand out multiple concurrent connections unless told
// otherwise -- under real concurrent load that surfaces as "database is
// locked" errors, not a graceful queue. Two things fix it, both applied
// here: (1) WAL journal mode + a busy_timeout set via connection-string
// pragmas, so a writer briefly blocks instead of erroring when it collides
// with another writer; (2) db.SetMaxOpenConns(1), which fully serializes
// every query -- including reads -- through one connection. That trades
// away WAL's concurrent-reader benefit, but this store's write volume
// (token issuance, revocation) is low enough that simplicity and
// correctness win over that squeezed-out read concurrency. Revisit only if
// profiling actually shows store access as a bottleneck.
type SQLiteStore struct {
	db *sql.DB
}

// sqliteURIPath escapes a filesystem path for use as the path component of
// a SQLite "file:" URI DSN. SQLite's URI-filename syntax treats a literal
// '?' as introducing the query string and '#' as introducing a fragment
// (see SQLite docs, "URI Filenames"); an unescaped path containing either
// would be truncated there, silently opening the wrong file, and lets the
// remainder of the path be interpreted as (and inject) extra
// pragmas/query parameters. '%' is escaped first so its own encoding
// round-trips correctly.
func sqliteURIPath(path string) string {
	r := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23")
	return r.Replace(path)
}

// Open creates (if needed) the SQLite file at path, applies every
// not-yet-applied migration, and returns a ready Store.
func Open(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", sqliteURIPath(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1) // see write-concurrency note above

	if err := applyMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Ping() error  { return s.db.Ping() }
func (s *SQLiteStore) Close() error { return s.db.Close() }

func (s *SQLiteStore) CreateUser(ctx context.Context, username, passwordHash string) (User, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`, username, passwordHash)
	if err != nil {
		if isUniqueConstraint(err) {
			return User{}, ErrConflict
		}
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return s.GetUserByID(ctx, id)
}

func (s *SQLiteStore) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *SQLiteStore) GetUserByID(ctx context.Context, id int64) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *SQLiteStore) GetUserByExternalIdentity(ctx context.Context, issuer, subject string) (User, error) {
	var u User
	err := s.db.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.created_at
		 FROM users u
		 JOIN external_identities ei ON ei.user_id = u.id
		 WHERE ei.issuer = ? AND ei.subject = ?`, issuer, subject,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *SQLiteStore) LinkExternalIdentity(ctx context.Context, userID int64, issuer, subject string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO external_identities (user_id, issuer, subject) VALUES (?, ?, ?)`, userID, issuer, subject)
	if isUniqueConstraint(err) {
		return ErrConflict
	}
	return err
}

// ResolveOrCreateExternalUser runs the whole check-then-insert inside one
// transaction -- the write-concurrency doc comment on SQLiteStore already
// serializes every statement through a single connection, but without a
// transaction two concurrent first-logins for the same (issuer, subject)
// could still interleave their separate SELECT/INSERT round trips and
// create two different user rows, one of them orphaned when its
// external_identities INSERT loses the UNIQUE(issuer, subject) race. A
// transaction holds the connection for its whole duration, so that
// interleaving can't happen.
func (s *SQLiteStore) ResolveOrCreateExternalUser(ctx context.Context, issuer, subject, newUsername, newPasswordHash string) (User, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, false, err
	}
	defer func() { _ = tx.Rollback() }() // no-op if already committed

	var u User
	err = tx.QueryRowContext(ctx,
		`SELECT u.id, u.username, u.password_hash, u.created_at
		 FROM users u
		 JOIN external_identities ei ON ei.user_id = u.id
		 WHERE ei.issuer = ? AND ei.subject = ?`, issuer, subject,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt)
	if err == nil {
		return u, false, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return User{}, false, err
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`, newUsername, newPasswordHash)
	if err != nil {
		return User{}, false, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, false, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO external_identities (user_id, issuer, subject) VALUES (?, ?, ?)`, id, issuer, subject,
	); err != nil {
		return User{}, false, err
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT id, username, password_hash, created_at FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.CreatedAt); err != nil {
		return User{}, false, err
	}
	return u, true, tx.Commit()
}

func (s *SQLiteStore) CreateAgent(ctx context.Context, clientID, secretHash, name string) (Agent, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO agents (client_id, secret_hash, name) VALUES (?, ?, ?)`, clientID, secretHash, name)
	if err != nil {
		if isUniqueConstraint(err) {
			return Agent{}, ErrConflict
		}
		return Agent{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Agent{}, err
	}
	return s.GetAgentByID(ctx, id)
}

func (s *SQLiteStore) GetAgentByClientID(ctx context.Context, clientID string) (Agent, error) {
	var a Agent
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, secret_hash, name, created_at, revoked_at FROM agents WHERE client_id = ?`, clientID,
	).Scan(&a.ID, &a.ClientID, &a.SecretHash, &a.Name, &a.CreatedAt, &a.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

func (s *SQLiteStore) GetAgentByID(ctx context.Context, id int64) (Agent, error) {
	var a Agent
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, secret_hash, name, created_at, revoked_at FROM agents WHERE id = ?`, id,
	).Scan(&a.ID, &a.ClientID, &a.SecretHash, &a.Name, &a.CreatedAt, &a.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

// ListAgents intentionally never selects secret_hash: its only caller
// (GET /admin/agents) never uses or returns it, so there's no reason to
// pull credential material into memory and increase the blast radius of
// accidental logging or future reuse of these Agent structs. Callers that
// actually need a secret hash (auth verification) go through
// GetAgentByClientID/GetAgentByID instead.
func (s *SQLiteStore) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, created_at, revoked_at FROM agents ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.ClientID, &a.Name, &a.CreatedAt, &a.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) RevokeAgent(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE agents SET revoked_at = CURRENT_TIMESTAMP WHERE client_id = ? AND revoked_at IS NULL`, clientID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	// Zero rows affected means either the agent doesn't exist, or it's
	// already revoked (the WHERE clause excludes it either way) --
	// idempotent revocation means "already revoked" isn't an error, so
	// look the agent up to tell the two cases apart.
	if _, err := s.GetAgentByClientID(ctx, clientID); err != nil {
		return err // ErrNotFound, or a real lookup error
	}
	return nil
}

// CreateProxy/GetProxyByClientID/GetProxyByID/ListProxies/RevokeProxy
// (issue #63) are the Proxy-table twins of the five Agent methods just
// above -- identical logic against the separate `proxies` table.
func (s *SQLiteStore) CreateProxy(ctx context.Context, clientID, secretHash, name string) (Proxy, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO proxies (client_id, secret_hash, name) VALUES (?, ?, ?)`, clientID, secretHash, name)
	if err != nil {
		if isUniqueConstraint(err) {
			return Proxy{}, ErrConflict
		}
		return Proxy{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Proxy{}, err
	}
	return s.GetProxyByID(ctx, id)
}

func (s *SQLiteStore) GetProxyByClientID(ctx context.Context, clientID string) (Proxy, error) {
	var p Proxy
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, secret_hash, name, created_at, revoked_at FROM proxies WHERE client_id = ?`, clientID,
	).Scan(&p.ID, &p.ClientID, &p.SecretHash, &p.Name, &p.CreatedAt, &p.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrNotFound
	}
	return p, err
}

func (s *SQLiteStore) GetProxyByID(ctx context.Context, id int64) (Proxy, error) {
	var p Proxy
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, secret_hash, name, created_at, revoked_at FROM proxies WHERE id = ?`, id,
	).Scan(&p.ID, &p.ClientID, &p.SecretHash, &p.Name, &p.CreatedAt, &p.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrNotFound
	}
	return p, err
}

// ListProxies intentionally never selects secret_hash -- same reasoning
// as ListAgents just above.
func (s *SQLiteStore) ListProxies(ctx context.Context) ([]Proxy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, client_id, name, created_at, revoked_at FROM proxies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Proxy
	for rows.Next() {
		var p Proxy
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.CreatedAt, &p.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) RevokeProxy(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE proxies SET revoked_at = CURRENT_TIMESTAMP WHERE client_id = ? AND revoked_at IS NULL`, clientID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := s.GetProxyByClientID(ctx, clientID); err != nil {
		return err // ErrNotFound, or a real lookup error
	}
	return nil
}

func (s *SQLiteStore) CreateGroup(ctx context.Context, name string) (Group, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO groups (name) VALUES (?)`, name)
	if err != nil {
		if isUniqueConstraint(err) {
			return Group{}, ErrConflict
		}
		return Group{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Group{}, err
	}
	return Group{ID: id, Name: name}, nil
}

func (s *SQLiteStore) GetGroupByName(ctx context.Context, name string) (Group, error) {
	var g Group
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name FROM groups WHERE name = ?`, name,
	).Scan(&g.ID, &g.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	return g, err
}

func (s *SQLiteStore) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGroups(rows)
}

// DeleteGroup's referenced-by-policy check and the delete itself run
// inside one transaction (issue found by Copilot's review on PR #14):
// as three separate statements, a policy could be inserted referencing
// this group between the COUNT and the DELETE, and the DELETE would
// then silently cascade-wipe that just-created policy -- exactly what
// this check exists to prevent. With MaxOpenConns(1) (see this file's
// top-of-file write-concurrency comment), wrapping in a transaction
// doesn't just close a logical race: it holds the store's one
// connection for the whole check+delete, so a concurrent caller's own
// statement genuinely cannot interleave between them -- it blocks for
// a connection until this transaction commits or rolls back.
func (s *SQLiteStore) DeleteGroup(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }() // no-op if already committed

	var groupID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM groups WHERE name = ?`, name).Scan(&groupID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	var refCount int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policies WHERE group_id = ?`, groupID,
	).Scan(&refCount); err != nil {
		return err
	}
	if refCount > 0 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, groupID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) AssignUserGroup(ctx context.Context, userID, groupID int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)`, userID, groupID)
	return err
}

func (s *SQLiteStore) AssignAgentGroup(ctx context.Context, agentID, groupID int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO agent_groups (agent_id, group_id) VALUES (?, ?)`, agentID, groupID)
	return err
}

func (s *SQLiteStore) RemoveUserGroup(ctx context.Context, userID, groupID int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
	return err
}

func (s *SQLiteStore) RemoveAgentGroup(ctx context.Context, agentID, groupID int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM agent_groups WHERE agent_id = ? AND group_id = ?`, agentID, groupID)
	return err
}

func (s *SQLiteStore) UserGroups(ctx context.Context, userID int64) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.id, g.name FROM groups g
		 JOIN user_groups ug ON ug.group_id = g.id
		 WHERE ug.user_id = ? ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGroups(rows)
}

func (s *SQLiteStore) AgentGroups(ctx context.Context, agentID int64) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT g.id, g.name FROM groups g
		 JOIN agent_groups ag ON ag.group_id = g.id
		 WHERE ag.agent_id = ? ORDER BY g.name`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanGroups(rows)
}

func scanGroups(rows *sql.Rows) ([]Group, error) {
	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *SQLiteStore) RevokeJTI(ctx context.Context, jti string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO revocations (jti, expires_at) VALUES (?, ?)`, jti, expiresAt)
	return err
}

func (s *SQLiteStore) IsRevoked(ctx context.Context, jti string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM revocations WHERE jti = ? AND expires_at > ?`, jti, time.Now()).Scan(&count)
	return count > 0, err
}

func (s *SQLiteStore) LoadRevocations(ctx context.Context) ([]Revocation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT jti, expires_at, revoked_at FROM revocations WHERE expires_at > ?`, time.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var revs []Revocation
	for rows.Next() {
		var r Revocation
		if err := rows.Scan(&r.JTI, &r.ExpiresAt, &r.RevokedAt); err != nil {
			return nil, err
		}
		revs = append(revs, r)
	}
	return revs, rows.Err()
}

// ReplacePolicies runs inside one transaction: delete every existing
// policy row, then insert the given set. Config is the sole source of
// policy truth in this phase -- see the Store interface's doc comment for
// why full replacement, not diffing, is the right idempotency strategy
// here specifically (unlike identity data).
func (s *SQLiteStore) ReplacePolicies(ctx context.Context, policies []NewPolicy) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM policies`); err != nil {
		return fmt.Errorf("clear policies: %w", err)
	}
	for _, p := range policies {
		methodsJSON, err := json.Marshal(nonNilStrings(p.Methods))
		if err != nil {
			return fmt.Errorf("marshal methods: %w", err)
		}
		toolsJSON, err := json.Marshal(nonNilStrings(p.Tools))
		if err != nil {
			return fmt.Errorf("marshal tools: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO policies (group_id, node, rule_type, methods, tools, rate_limit_max_calls, rate_limit_window_seconds, block_on_scan_flag)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.GroupID, p.Node, string(p.RuleType), string(methodsJSON), string(toolsJSON),
			p.RateLimitMaxCalls, p.RateLimitWindowSeconds, p.BlockOnScanFlag,
		); err != nil {
			return fmt.Errorf("insert policy for group %d node %q: %w", p.GroupID, p.Node, err)
		}
	}
	return tx.Commit()
}

const policyColumns = `id, group_id, node, rule_type, methods, tools, rate_limit_max_calls, rate_limit_window_seconds, block_on_scan_flag, created_at`

func (s *SQLiteStore) PoliciesForGroups(ctx context.Context, groupIDs []int64, node string) ([]Policy, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(groupIDs))
	args := make([]any, 0, len(groupIDs)+1)
	for i, id := range groupIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	args = append(args, node)

	query := fmt.Sprintf(
		`SELECT `+policyColumns+`
		 FROM policies WHERE group_id IN (%s) AND node = ?`, strings.Join(placeholders, ","))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

// AllPolicies returns every policy row, unfiltered -- the admin API's
// GET /admin/policies (issue #13) needs to show the complete current
// rule set, not one scoped to a specific principal's groups the way
// PoliciesForGroups (the evaluator's hot-path query) is.
func (s *SQLiteStore) AllPolicies(ctx context.Context) ([]Policy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+policyColumns+` FROM policies ORDER BY node, group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPolicies(rows)
}

func scanPolicies(rows *sql.Rows) ([]Policy, error) {
	var out []Policy
	for rows.Next() {
		var p Policy
		var ruleType, methodsJSON, toolsJSON string
		if err := rows.Scan(&p.ID, &p.GroupID, &p.Node, &ruleType, &methodsJSON, &toolsJSON,
			&p.RateLimitMaxCalls, &p.RateLimitWindowSeconds, &p.BlockOnScanFlag, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.RuleType = PolicyRuleType(ruleType)
		if err := json.Unmarshal([]byte(methodsJSON), &p.Methods); err != nil {
			return nil, fmt.Errorf("unmarshal methods for policy %d: %w", p.ID, err)
		}
		if err := json.Unmarshal([]byte(toolsJSON), &p.Tools); err != nil {
			return nil, fmt.Errorf("unmarshal tools for policy %d: %w", p.ID, err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *SQLiteStore) GetToolPin(ctx context.Context, node, toolName string) (ToolPin, error) {
	var p ToolPin
	err := s.db.QueryRowContext(ctx,
		`SELECT id, node, tool_name, hash, input_schema, pinned_at, quarantined_at, drift_detail
		 FROM tool_pins WHERE node = ? AND tool_name = ?`, node, toolName,
	).Scan(&p.ID, &p.Node, &p.ToolName, &p.Hash, &p.InputSchema, &p.PinnedAt, &p.QuarantinedAt, &p.DriftDetail)
	if errors.Is(err, sql.ErrNoRows) {
		return ToolPin{}, ErrNotFound
	}
	return p, err
}

func (s *SQLiteStore) CreateToolPin(ctx context.Context, node, toolName, hash, inputSchema string) (ToolPin, error) {
	var schema any // NULL when empty, not an empty-string row -- distinguishes "no inputSchema was ever pinned" from "one was pinned and happened to be empty"
	if inputSchema != "" {
		schema = inputSchema
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO tool_pins (node, tool_name, hash, input_schema) VALUES (?, ?, ?, ?)`, node, toolName, hash, schema)
	if err != nil {
		if isUniqueConstraint(err) {
			return ToolPin{}, ErrConflict
		}
		return ToolPin{}, err
	}
	return s.GetToolPin(ctx, node, toolName)
}

func (s *SQLiteStore) QuarantineToolPin(ctx context.Context, node, toolName, driftDetail string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE tool_pins SET quarantined_at = CURRENT_TIMESTAMP, drift_detail = ?
		 WHERE node = ? AND tool_name = ?`, driftDetail, node, toolName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) ToolPinsForNode(ctx context.Context, node string) ([]ToolPin, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, node, tool_name, hash, input_schema, pinned_at, quarantined_at, drift_detail
		 FROM tool_pins WHERE node = ?`, node)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ToolPin
	for rows.Next() {
		var p ToolPin
		if err := rows.Scan(&p.ID, &p.Node, &p.ToolName, &p.Hash, &p.InputSchema, &p.PinnedAt, &p.QuarantinedAt, &p.DriftDetail); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ListQuarantinedToolPins(ctx context.Context) ([]ToolPin, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, node, tool_name, hash, input_schema, pinned_at, quarantined_at, drift_detail
		 FROM tool_pins WHERE quarantined_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ToolPin
	for rows.Next() {
		var p ToolPin
		if err := rows.Scan(&p.ID, &p.Node, &p.ToolName, &p.Hash, &p.InputSchema, &p.PinnedAt, &p.QuarantinedAt, &p.DriftDetail); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ApproveToolPin(ctx context.Context, node, toolName, newHash, newInputSchema string) error {
	var schema any // NULL when empty, same convention CreateToolPin already uses
	if newInputSchema != "" {
		schema = newInputSchema
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE tool_pins SET hash = ?, input_schema = ?, pinned_at = CURRENT_TIMESTAMP,
		 quarantined_at = NULL, drift_detail = NULL
		 WHERE node = ? AND tool_name = ?`, newHash, schema, node, toolName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) CreateNode(ctx context.Context, n Node) (Node, error) {
	argsJSON, err := marshalNodeArgs(n.Args)
	if err != nil {
		return Node{}, err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO mcp_nodes (name, transport, upstream_url, command, args, pin_refresh_interval_seconds, source)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		n.Name, n.Transport, n.UpstreamURL, n.Command, argsJSON, n.PinRefreshIntervalSeconds, n.Source)
	if err != nil {
		if isUniqueConstraint(err) {
			return Node{}, ErrConflict
		}
		return Node{}, err
	}
	return s.GetNodeByName(ctx, n.Name)
}

func (s *SQLiteStore) GetNodeByName(ctx context.Context, name string) (Node, error) {
	var n Node
	var argsJSON *string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, transport, upstream_url, command, args, pin_refresh_interval_seconds, source, created_at
		 FROM mcp_nodes WHERE name = ?`, name,
	).Scan(&n.ID, &n.Name, &n.Transport, &n.UpstreamURL, &n.Command, &argsJSON, &n.PinRefreshIntervalSeconds, &n.Source, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	if err != nil {
		return Node{}, err
	}
	if err := unmarshalNodeArgs(argsJSON, &n); err != nil {
		return Node{}, err
	}
	return n, nil
}

// UpsertConfigNode: see the Store interface's doc comment for the full
// "config stays authoritative for its own rows, never silently
// overwrites an admin-registered one" contract.
func (s *SQLiteStore) UpsertConfigNode(ctx context.Context, n Node) (Node, error) {
	existing, err := s.GetNodeByName(ctx, n.Name)
	if errors.Is(err, ErrNotFound) {
		n.Source = NodeSourceConfig
		return s.CreateNode(ctx, n)
	}
	if err != nil {
		return Node{}, err
	}
	if existing.Source != NodeSourceConfig {
		return Node{}, ErrConflict
	}
	argsJSON, err := marshalNodeArgs(n.Args)
	if err != nil {
		return Node{}, err
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE mcp_nodes SET transport = ?, upstream_url = ?, command = ?, args = ?, pin_refresh_interval_seconds = ?
		 WHERE name = ?`,
		n.Transport, n.UpstreamURL, n.Command, argsJSON, n.PinRefreshIntervalSeconds, n.Name,
	); err != nil {
		return Node{}, err
	}
	return s.GetNodeByName(ctx, n.Name)
}

func (s *SQLiteStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, transport, upstream_url, command, args, pin_refresh_interval_seconds, source, created_at
		 FROM mcp_nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		var n Node
		var argsJSON *string
		if err := rows.Scan(&n.ID, &n.Name, &n.Transport, &n.UpstreamURL, &n.Command, &argsJSON, &n.PinRefreshIntervalSeconds, &n.Source, &n.CreatedAt); err != nil {
			return nil, err
		}
		if err := unmarshalNodeArgs(argsJSON, &n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) DeleteNode(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mcp_nodes WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func marshalNodeArgs(args []string) (any, error) {
	if len(args) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal node args: %w", err)
	}
	return string(b), nil
}

func unmarshalNodeArgs(argsJSON *string, n *Node) error {
	if argsJSON == nil {
		return nil
	}
	if err := json.Unmarshal([]byte(*argsJSON), &n.Args); err != nil {
		return fmt.Errorf("unmarshal args for node %s: %w", n.Name, err)
	}
	return nil
}

// AppendAuditRecord persists rec as the new last entry in the
// hash-chained audit log (issue #23). The read-last-hash-then-insert
// happens inside one transaction -- the same atomicity precedent
// ResolveOrCreateExternalUser already established -- so concurrent
// appends can never race each other into computing the same prevHash
// for two different rows.
func (s *SQLiteStore) AppendAuditRecord(ctx context.Context, rec audit.Record) (AuditLogEntry, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AuditLogEntry{}, err
	}
	defer func() { _ = tx.Rollback() }() // no-op if already committed

	prevHash := audit.GenesisPrevHash
	var lastHash string
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&lastHash)
	switch {
	case err == nil:
		prevHash = lastHash
	case errors.Is(err, sql.ErrNoRows):
		// Table is empty -- prevHash stays the genesis sentinel.
	default:
		return AuditLogEntry{}, err
	}

	hash, err := audit.Hash(prevHash, rec)
	if err != nil {
		return AuditLogEntry{}, err
	}

	var actorNHISubject any
	if rec.ActorNHISubject != "" {
		actorNHISubject = rec.ActorNHISubject
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log (ts, actor_nhi_subject, actor_human_username, actor_human_role, action, resource, prev_hash, hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Timestamp, actorNHISubject, rec.ActorHumanUsername, rec.ActorHumanRole, rec.Action, rec.Resource, prevHash, hash)
	if err != nil {
		return AuditLogEntry{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return AuditLogEntry{}, err
	}
	if err := tx.Commit(); err != nil {
		return AuditLogEntry{}, err
	}

	return AuditLogEntry{
		ID: id,
		StoredRecord: audit.StoredRecord{
			Record:   rec,
			PrevHash: prevHash,
			Hash:     hash,
		},
	}, nil
}

// ListAuditRecords returns every audit_log row in chain order
// (ascending id).
func (s *SQLiteStore) ListAuditRecords(ctx context.Context) ([]AuditLogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, actor_nhi_subject, actor_human_username, actor_human_role, action, resource, prev_hash, hash
		 FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		var actorNHISubject sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &actorNHISubject, &e.ActorHumanUsername,
			&e.ActorHumanRole, &e.Action, &e.Resource, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.ActorNHISubject = actorNHISubject.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// ListAuditRecordsPage returns up to limit rows in descending id order
// (most recent first), starting just before beforeID -- see the
// Store interface doc comment for the limit/beforeID semantics.
func (s *SQLiteStore) ListAuditRecordsPage(ctx context.Context, limit int, beforeID int64) ([]AuditLogEntry, error) {
	if limit <= 0 {
		limit = DefaultAuditPageSize
	}
	if limit > MaxAuditPageSize {
		limit = MaxAuditPageSize
	}

	var rows *sql.Rows
	var err error
	if beforeID <= 0 {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, ts, actor_nhi_subject, actor_human_username, actor_human_role, action, resource, prev_hash, hash
			 FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, ts, actor_nhi_subject, actor_human_username, actor_human_role, action, resource, prev_hash, hash
			 FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`, beforeID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditLogEntry
	for rows.Next() {
		var e AuditLogEntry
		var actorNHISubject sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &actorNHISubject, &e.ActorHumanUsername,
			&e.ActorHumanRole, &e.Action, &e.Resource, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.ActorNHISubject = actorNHISubject.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// isUniqueConstraint reports whether err came from a UNIQUE constraint
// violation. modernc.org/sqlite doesn't export a typed error for this, so
// this falls back to matching the driver's message text.
func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
