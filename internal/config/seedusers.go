package config

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// SeedUser is one config-bootstrap local (Mode A) human account (issue
// #21) -- the CSV-sourced equivalent of SeedAgent, for deployments
// standing up the gateway without spider-snoop (see the issue #21
// spec's Problem Statement for why this is a config-bootstrap
// mechanism rather than an admin-API/UI feature). Not part of
// config.json's own JSON schema -- populated by parsing the file
// Config.SeedUsersCSVPath points at, the same "Load reads it, cmd/
// spidercob bootstraps it" split ValidateNode's callers already use.
type SeedUser struct {
	Username string
	// Password is plaintext here, exactly as SeedAgent.ClientSecret
	// already is -- hashed once at import time (cmd/spidercob, via
	// identity.Service.CreateUser) and never persisted as-is. Same
	// documented caveat: a secret written into a config-adjacent file
	// is weaker than a generated one; this bootstrap mechanism trades
	// that for the "provision a whole team in one step" story a
	// standalone, no-IAM-department deployment actually needs.
	Password string
	// Groups assigns this user to the named groups at startup (auto-
	// creating any that don't already exist) -- mirrors SeedAgent.Groups
	// exactly.
	Groups []string
}

// ParseSeedUsersCSV parses a CSV of local users to bootstrap (issue
// #21) -- a pure function, no file I/O, so tests exercise it directly
// against an in-memory reader, the same posture ValidateNode already
// established for issue #15. Config.Load owns the actual file read;
// this only ever sees bytes already in hand.
//
// Expects a header row naming "username", "password", and optionally
// "groups" columns, case-insensitively, in any order -- an operator's
// spreadsheet export shouldn't need to match an exact column sequence.
// A groups cell (when present) is split on ";" (not "," -- that's
// already the CSV's own field delimiter) and each piece trimmed.
//
// Fails loud, never skip-and-continue, on: a missing username or
// password header column; an empty username or password value in any
// data row; two rows sharing the same username (a config-authoring
// mistake, not something to silently resolve via last-row-wins).
func ParseSeedUsersCSV(r io.Reader) ([]SeedUser, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true

	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("seed users csv: read header: %w", err)
	}

	usernameCol, passwordCol, groupsCol := -1, -1, -1
	for i, col := range header {
		switch strings.ToLower(strings.TrimSpace(col)) {
		case "username":
			usernameCol = i
		case "password":
			passwordCol = i
		case "groups":
			groupsCol = i
		}
	}
	if usernameCol == -1 {
		return nil, fmt.Errorf("seed users csv: missing required %q column", "username")
	}
	if passwordCol == -1 {
		return nil, fmt.Errorf("seed users csv: missing required %q column", "password")
	}

	var users []SeedUser
	seen := make(map[string]bool)
	rowNum := 1 // header was row 1
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("seed users csv: %w", err)
		}
		rowNum++

		username := strings.TrimSpace(row[usernameCol])
		password := strings.TrimSpace(row[passwordCol])
		if username == "" {
			return nil, fmt.Errorf("seed users csv: row %d: username is empty", rowNum)
		}
		if password == "" {
			return nil, fmt.Errorf("seed users csv: row %d: password is empty", rowNum)
		}
		if seen[username] {
			return nil, fmt.Errorf("seed users csv: row %d: duplicate username %q", rowNum, username)
		}
		seen[username] = true

		var groups []string
		if groupsCol != -1 && groupsCol < len(row) {
			for _, g := range strings.Split(row[groupsCol], ";") {
				g = strings.TrimSpace(g)
				if g != "" {
					groups = append(groups, g)
				}
			}
		}

		users = append(users, SeedUser{Username: username, Password: password, Groups: groups})
	}
	return users, nil
}
