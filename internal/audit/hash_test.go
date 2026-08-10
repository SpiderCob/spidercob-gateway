package audit

import (
	"strings"
	"testing"
	"time"
)

func testRecord(action, resource string) Record {
	return Record{
		Timestamp:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		ActorNHISubject:    "agent:spider-snoop-backend",
		ActorHumanUsername: "alice",
		ActorHumanRole:     "admin",
		Action:             action,
		Resource:           resource,
	}
}

func TestHash_DeterministicForSameInputs(t *testing.T) {
	rec := testRecord("create_agent", "agt_123")
	h1, err := Hash(GenesisPrevHash, rec)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	h2, err := Hash(GenesisPrevHash, rec)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if h1 != h2 {
		t.Fatalf("Hash is not deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("Hash length = %d, want 64 (sha256 hex)", len(h1))
	}
}

func TestHash_ChangesIfAnyFieldChanges(t *testing.T) {
	base := testRecord("create_agent", "agt_123")
	baseHash, err := Hash(GenesisPrevHash, base)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	cases := []struct {
		name string
		mut  func(r Record) Record
	}{
		{"timestamp", func(r Record) Record { r.Timestamp = r.Timestamp.Add(time.Second); return r }},
		{"actor nhi subject", func(r Record) Record { r.ActorNHISubject = "agent:other"; return r }},
		{"actor human username", func(r Record) Record { r.ActorHumanUsername = "bob"; return r }},
		{"actor human role", func(r Record) Record { r.ActorHumanRole = "superadmin"; return r }},
		{"action", func(r Record) Record { r.Action = "revoke_agent"; return r }},
		{"resource", func(r Record) Record { r.Resource = "agt_456"; return r }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mutated := c.mut(base)
			got, err := Hash(GenesisPrevHash, mutated)
			if err != nil {
				t.Fatalf("Hash: %v", err)
			}
			if got == baseHash {
				t.Fatalf("Hash did not change after mutating %s", c.name)
			}
		})
	}
}

func TestHash_ChangesWithPrevHash(t *testing.T) {
	rec := testRecord("create_agent", "agt_123")
	h1, _ := Hash(GenesisPrevHash, rec)
	h2, _ := Hash("some-other-prev-hash", rec)
	if h1 == h2 {
		t.Fatal("Hash did not change when prevHash changed")
	}
}

func TestGenesisPrevHash_Is64Chars(t *testing.T) {
	if len(GenesisPrevHash) != 64 {
		t.Fatalf("GenesisPrevHash length = %d, want 64", len(GenesisPrevHash))
	}
	if strings.Trim(GenesisPrevHash, "0") != "" {
		t.Fatalf("GenesisPrevHash = %q, want all zeros", GenesisPrevHash)
	}
}

// chainOf builds a real, correctly-linked chain of StoredRecords from
// records -- the same construction AppendAuditRecord will do for real,
// but done directly here so Verify's tests don't need a store.
func chainOf(t *testing.T, records ...Record) []StoredRecord {
	t.Helper()
	prev := GenesisPrevHash
	var out []StoredRecord
	for _, rec := range records {
		h, err := Hash(prev, rec)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		out = append(out, StoredRecord{Record: rec, PrevHash: prev, Hash: h})
		prev = h
	}
	return out
}

func TestVerify_ValidChainPasses(t *testing.T) {
	chain := chainOf(t,
		testRecord("create_agent", "agt_1"),
		testRecord("create_group", "engineering"),
		testRecord("delete_node", "jira"),
	)
	if err := Verify(chain); err != nil {
		t.Fatalf("Verify on a valid chain: %v", err)
	}
}

func TestVerify_EmptyChainPasses(t *testing.T) {
	if err := Verify(nil); err != nil {
		t.Fatalf("Verify on an empty chain: %v", err)
	}
}

func TestVerify_TamperedRecordDetected(t *testing.T) {
	chain := chainOf(t,
		testRecord("create_agent", "agt_1"),
		testRecord("create_group", "engineering"),
		testRecord("delete_node", "jira"),
	)
	// Tamper with the middle record's Resource without recomputing its
	// Hash -- exactly what an attacker editing the DB directly would
	// produce.
	chain[1].Resource = "something-else"

	err := Verify(chain)
	if err == nil {
		t.Fatal("Verify did not detect a tampered record")
	}
	if !strings.Contains(err.Error(), "1") {
		t.Fatalf("Verify error %q does not identify record index 1", err.Error())
	}
}

func TestVerify_ReorderedRecordsDetected(t *testing.T) {
	chain := chainOf(t,
		testRecord("create_agent", "agt_1"),
		testRecord("create_group", "engineering"),
	)
	chain[0], chain[1] = chain[1], chain[0]

	if err := Verify(chain); err == nil {
		t.Fatal("Verify did not detect reordered records")
	}
}

func TestVerify_WrongGenesisPrevHashDetected(t *testing.T) {
	chain := chainOf(t, testRecord("create_agent", "agt_1"))
	chain[0].PrevHash = "not-the-real-genesis-hash-padded-out-to-sixty-four-characters!!"

	if err := Verify(chain); err == nil {
		t.Fatal("Verify did not detect a first record with the wrong genesis prev-hash")
	}
}
