package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

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

// Open creates (if needed) the SQLite file at path, applies every
// not-yet-applied migration, and returns a ready Store.
func Open(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
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
		`SELECT id, client_id, secret_hash, name, created_at FROM agents WHERE client_id = ?`, clientID,
	).Scan(&a.ID, &a.ClientID, &a.SecretHash, &a.Name, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
}

func (s *SQLiteStore) GetAgentByID(ctx context.Context, id int64) (Agent, error) {
	var a Agent
	err := s.db.QueryRowContext(ctx,
		`SELECT id, client_id, secret_hash, name, created_at FROM agents WHERE id = ?`, id,
	).Scan(&a.ID, &a.ClientID, &a.SecretHash, &a.Name, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Agent{}, ErrNotFound
	}
	return a, err
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
		`SELECT COUNT(*) FROM revocations WHERE jti = ?`, jti).Scan(&count)
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

// isUniqueConstraint reports whether err came from a UNIQUE constraint
// violation. modernc.org/sqlite doesn't export a typed error for this, so
// this falls back to matching the driver's message text.
func isUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
