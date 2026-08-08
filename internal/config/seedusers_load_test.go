package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeSeedUsersCSV(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.csv")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write seed users csv: %v", err)
	}
	return path
}

func writeConfigWithSeedUsersCSVPath(t *testing.T, csvPath string) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"nodes":               []any{},
		"seed_users_csv_path": csvPath,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return writeConfig(t, string(body))
}

func TestLoad_SeedUsersCSVPathPopulatesSeedUsers(t *testing.T) {
	csvPath := writeSeedUsersCSV(t, "username,password,groups\nalice,s3cret,engineering\n")
	cfg, err := Load(writeConfigWithSeedUsersCSVPath(t, csvPath))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SeedUsers) != 1 {
		t.Fatalf("SeedUsers = %+v, want 1 entry", cfg.SeedUsers)
	}
	got := cfg.SeedUsers[0]
	if got.Username != "alice" || got.Password != "s3cret" || len(got.Groups) != 1 || got.Groups[0] != "engineering" {
		t.Fatalf("SeedUsers[0] = %+v", got)
	}
}

func TestLoad_SeedUsersCSVPathMissingFileFails(t *testing.T) {
	path := writeConfigWithSeedUsersCSVPath(t, filepath.Join(t.TempDir(), "does-not-exist.csv"))
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a seed_users_csv_path pointing at a nonexistent file")
	}
}

func TestLoad_SeedUsersCSVPathMalformedContentFails(t *testing.T) {
	csvPath := writeSeedUsersCSV(t, "username,password\nalice,\n") // empty password
	path := writeConfigWithSeedUsersCSVPath(t, csvPath)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a malformed seed users csv")
	}
}

func TestLoad_NoSeedUsersCSVPathLeavesSeedUsersEmpty(t *testing.T) {
	path := writeConfig(t, `{"nodes":[]}`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.SeedUsers) != 0 {
		t.Fatalf("SeedUsers = %+v, want empty", cfg.SeedUsers)
	}
}
