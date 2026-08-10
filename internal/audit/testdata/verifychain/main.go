// Command verifychain is a real, minimal fixture (issue #23) that opens
// a gateway's store_db_path directly and verifies its audit_log's hash
// chain -- not a mock. There's no HTTP endpoint that exposes audit
// records yet (out of scope for this issue), so this is how
// automation/run-e2e-audit.sh proves the chain is both actually
// persisted and actually tamper-evident against a real SQLite file, the
// same "drive the real thing, not a simulation" posture every other e2e
// script in this repo already takes.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: verifychain <store_db_path>")
		os.Exit(2)
	}
	s, err := store.Open(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	entries, err := s.ListAuditRecords(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "list audit records: %v\n", err)
		os.Exit(1)
	}

	stored := make([]audit.StoredRecord, len(entries))
	for i, e := range entries {
		stored[i] = e.StoredRecord
	}

	fmt.Printf("record_count=%d\n", len(stored))
	if err := audit.Verify(stored); err != nil {
		fmt.Printf("verify=fail err=%v\n", err)
		os.Exit(1)
	}
	fmt.Println("verify=pass")
}
