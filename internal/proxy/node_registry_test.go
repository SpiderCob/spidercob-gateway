package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/config"
	"github.com/sumeetgp/spidercob-gateway/internal/policy"
)

// newEmptyTestGateway builds a Gateway with zero configured nodes -- the
// shape every AddNode/RemoveNode test starts from, proving nodes reach
// the routing table exclusively through the new live-registration seam,
// not through New's own construction loop.
func newEmptyTestGateway(t *testing.T) *Gateway {
	t.Helper()
	gw, err := New(&config.Config{Listen: ":0"}, fakeValidator{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	gw.policy = policy.AllowAll{}
	t.Cleanup(func() {
		if err := gw.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return gw
}

func unknownNodeStatus(t *testing.T, gw *Gateway, node string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp/"+node+"/", strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	authorize(req)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec.Code
}

func TestGateway_AddNode_HTTPTransport_MakesNodeImmediatelyRoutable(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newEmptyTestGateway(t)

	if got := unknownNodeStatus(t, gw, "late-jira"); got != http.StatusNotFound {
		t.Fatalf("before AddNode: status = %d, want 404", got)
	}

	if err := gw.AddNode(config.Node{Name: "late-jira", Transport: config.TransportStreamableHTTP, UpstreamURL: upstream.URL}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}

	sessionID, rec := initialize(t, gw, "late-jira")
	if rec.Code != http.StatusOK || sessionID == "" {
		t.Fatalf("after AddNode: initialize failed, status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestGateway_AddNode_RejectsDuplicateName(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newEmptyTestGateway(t)

	n := config.Node{Name: "dup", Transport: config.TransportStreamableHTTP, UpstreamURL: upstream.URL}
	if err := gw.AddNode(n); err != nil {
		t.Fatalf("first AddNode: %v", err)
	}
	if err := gw.AddNode(n); err == nil {
		t.Fatal("expected an error adding the same node name twice")
	}
}

func TestGateway_AddNode_RejectsInvalidNode(t *testing.T) {
	gw := newEmptyTestGateway(t)
	// No transport at all -- config.ValidateNode's job to reject this,
	// exercised here to prove AddNode actually calls it rather than
	// trusting the caller.
	if err := gw.AddNode(config.Node{Name: "bad"}); err == nil {
		t.Fatal("expected an error for a node with no transport")
	}
	if got := unknownNodeStatus(t, gw, "bad"); got != http.StatusNotFound {
		t.Fatalf("a rejected AddNode must not partially register the node: status = %d, want 404", got)
	}
}

func TestGateway_RemoveNode_MakesNodeImmediatelyUnroutable(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newEmptyTestGateway(t)

	if err := gw.AddNode(config.Node{Name: "temp", Transport: config.TransportStreamableHTTP, UpstreamURL: upstream.URL}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	if _, rec := initialize(t, gw, "temp"); rec.Code != http.StatusOK {
		t.Fatalf("sanity check before RemoveNode failed: status = %d", rec.Code)
	}

	if err := gw.RemoveNode("temp"); err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}
	if got := unknownNodeStatus(t, gw, "temp"); got != http.StatusNotFound {
		t.Fatalf("after RemoveNode: status = %d, want 404", got)
	}
}

func TestGateway_RemoveNode_DoesNotAffectAnAlreadyEstablishedSession(t *testing.T) {
	// Story 5: an in-flight session keeps working after the node it's on
	// is removed -- only *new* sessions are blocked.
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newEmptyTestGateway(t)

	if err := gw.AddNode(config.Node{Name: "survivor", Transport: config.TransportStreamableHTTP, UpstreamURL: upstream.URL}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	sessionID, _ := initialize(t, gw, "survivor")

	if err := gw.RemoveNode("survivor"); err != nil {
		t.Fatalf("RemoveNode: %v", err)
	}

	rec := doWithSession(gw, "survivor", sessionID, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("an already-established session must keep working after RemoveNode: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	if got := unknownNodeStatus(t, gw, "survivor"); got != http.StatusNotFound {
		t.Fatalf("a brand new session against the removed node must still be rejected: status = %d, want 404", got)
	}
}

func TestGateway_AddNode_StdioTransport(t *testing.T) {
	gw := newEmptyTestGateway(t)
	if err := gw.AddNode(config.Node{
		Name:      "late-echo",
		Transport: config.TransportStdio,
		Command:   "go",
		Args:      []string{"run", "./stdioadapter/testdata/echoserver"},
	}); err != nil {
		t.Fatalf("AddNode: %v", err)
	}
	sessionID, rec := initialize(t, gw, "late-echo")
	if rec.Code != http.StatusOK || sessionID == "" {
		t.Fatalf("initialize against a live-added stdio node failed: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestGateway_NodeRegistry_ConcurrentAddRemoveAndRouting is the race
// proof for story 10: routing (ServeHTTP, on whatever goroutines real
// traffic uses) and admin add/remove (on whatever goroutine an HTTP
// admin request uses) happen concurrently against the same map. Run
// with -race; correctness of the exact interleaving isn't asserted,
// only that nothing races.
func TestGateway_NodeRegistry_ConcurrentAddRemoveAndRouting(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newEmptyTestGateway(t)

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
			_ = gw.AddNode(config.Node{Name: "racer", Transport: config.TransportStreamableHTTP, UpstreamURL: upstream.URL})
			_ = gw.RemoveNode("racer")
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
			_ = unknownNodeStatus(t, gw, "racer")
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
