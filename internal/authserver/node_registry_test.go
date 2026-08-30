package authserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestAddNode_MakesTokenMintingAndMetadataWorkImmediately(t *testing.T) {
	env := newTestEnv(t, Config{}) // starts with only "jira" configured
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "late-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Before AddNode: minting for the not-yet-registered node fails, and
	// RFC 9728 metadata 404s.
	form := url.Values{
		"grant_type":    {grantClientCredentials},
		"client_id":     {agent.ClientID},
		"client_secret": {secret},
		"resource":      {"confluence"},
	}
	if rec := tokenRequest(t, env.as, form); rec.Code == http.StatusOK {
		t.Fatalf("expected minting to fail before AddNode, got 200: %s", rec.Body.String())
	}
	metaReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/confluence", nil)
	metaRec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(metaRec, metaReq)
	if metaRec.Code != http.StatusNotFound {
		t.Fatalf("expected metadata 404 before AddNode, got %d", metaRec.Code)
	}

	env.as.AddNode("confluence")

	rec := tokenRequest(t, env.as, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("minting after AddNode: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := env.as.ValidateAccessToken("confluence", resp.AccessToken); err != nil {
		t.Fatalf("ValidateAccessToken after AddNode: %v", err)
	}

	metaRec2 := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(metaRec2, metaReq)
	if metaRec2.Code != http.StatusOK {
		t.Fatalf("expected metadata 200 after AddNode, got %d: %s", metaRec2.Code, metaRec2.Body.String())
	}
}

func TestAddNode_Idempotent(t *testing.T) {
	env := newTestEnv(t, Config{})
	env.as.AddNode("confluence")
	env.as.AddNode("confluence") // must not panic or error
}

func TestRemoveNode_BlocksMintingAndMetadata_ButNotAnAlreadyIssuedToken(t *testing.T) {
	env := newTestEnv(t, Config{}) // "jira" is registered at construction
	ctx := context.Background()
	agent, secret, err := env.svc.CreateAgent(ctx, "outgoing-bot")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}

	// Mint a real token for "jira" *before* removing it.
	form := url.Values{
		"grant_type":    {grantClientCredentials},
		"client_id":     {agent.ClientID},
		"client_secret": {secret},
		"resource":      {"jira"},
	}
	mintRec := tokenRequest(t, env.as, form)
	if mintRec.Code != http.StatusOK {
		t.Fatalf("mint before RemoveNode: status = %d, body = %s", mintRec.Code, mintRec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(mintRec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	env.as.RemoveNode("jira")

	// Minting a *new* token for the now-removed node fails.
	if rec := tokenRequest(t, env.as, form); rec.Code == http.StatusOK {
		t.Fatalf("expected minting to fail after RemoveNode, got 200: %s", rec.Body.String())
	}
	// RFC 9728 metadata 404s.
	metaReq := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/jira", nil)
	metaRec := httptest.NewRecorder()
	env.as.Routes().ServeHTTP(metaRec, metaReq)
	if metaRec.Code != http.StatusNotFound {
		t.Fatalf("expected metadata 404 after RemoveNode, got %d", metaRec.Code)
	}
	// The token minted *before* removal still validates -- ValidateAccessToken
	// deliberately doesn't depend on a.nodes (issue #57 spec: an
	// already-established session on a removed node keeps working).
	if _, err := env.as.ValidateAccessToken("jira", resp.AccessToken); err != nil {
		t.Fatalf("expected the already-issued token to still validate after RemoveNode, got: %v", err)
	}
}

func TestRemoveNode_Idempotent(t *testing.T) {
	env := newTestEnv(t, Config{})
	env.as.RemoveNode("never-registered") // must not panic or error
}

// TestAuthServer_NodeRegistry_ConcurrentAddRemoveAndReads is the race
// proof: minting/metadata reads (on whatever goroutines real traffic
// uses) and admin add/remove (on whatever goroutine an HTTP admin
// request uses) happen concurrently against the same map. Run with
// -race.
func TestAuthServer_NodeRegistry_ConcurrentAddRemoveAndReads(t *testing.T) {
	env := newTestEnv(t, Config{})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			env.as.AddNode("racer")
			env.as.RemoveNode("racer")
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/racer", nil)
			rec := httptest.NewRecorder()
			env.as.Routes().ServeHTTP(rec, req)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
