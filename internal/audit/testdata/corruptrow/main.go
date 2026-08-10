// Command corruptrow is a real fixture (issue #23) that directly
// UPDATEs one audit_log row's resource column via raw SQL, bypassing
// store.Store's append-only interface entirely -- simulating exactly
// what an attacker (or a careless operator) with direct database
// access could do, which is the actual threat audit.Verify's
// tamper-evidence exists to catch. automation/run-e2e-audit.sh uses
// this to prove Verify really does detect a real, on-disk alteration,
// not just a hand-constructed one in a unit test.
package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: corruptrow <store_db_path> <row_id>")
		os.Exit(2)
	}
	db, err := sql.Open("sqlite", os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	res, err := db.Exec(`UPDATE audit_log SET resource = 'TAMPERED' WHERE id = ?`, os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: %v\n", err)
		os.Exit(1)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		fmt.Fprintf(os.Stderr, "expected to update exactly 1 row, updated %d\n", n)
		os.Exit(1)
	}
	fmt.Println("corrupted row", os.Args[2])
}
