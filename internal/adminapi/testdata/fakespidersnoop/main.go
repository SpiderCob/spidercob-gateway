// Command fakespidersnoop is a real, minimal HTTP fixture standing in
// for spider-snoop's GET /api/users/me during issue #13's real end-to-
// end proof (automation/run-e2e-adminapi.sh) -- not a mock. It always
// reports the same admin session, since that script exists to prove the
// gateway's own admin-API plumbing (the introspection call actually
// happens, actually gates on the response), not to re-test spider-
// snoop's own role logic -- that's spider-snoop's own test suite's job.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":8090"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	http.HandleFunc("/api/users/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"username": "alice", "role": "admin"})
	})
	log.Fatal(http.ListenAndServe(addr, nil))
}
