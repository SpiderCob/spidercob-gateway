package proxy

import (
	"context"
	"testing"
)

func TestGateway_FetchToolsForPin(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	tools, err := gw.FetchToolsForPin(context.Background(), "jira")
	if err != nil {
		t.Fatalf("FetchToolsForPin: %v", err)
	}

	names := make(map[string]bool, len(tools))
	for _, tl := range tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"search_issues", "delete_issue", "create_issue"} {
		if !names[want] {
			t.Fatalf("FetchToolsForPin result %v missing %q", tools, want)
		}
	}
}

func TestGateway_FetchToolsForPin_UnknownNode(t *testing.T) {
	upstream, _ := newFakeUpstreamServer()
	t.Cleanup(func() { upstream.Close() })
	gw := newHTTPTestGateway(t, upstream.URL)

	if _, err := gw.FetchToolsForPin(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("FetchToolsForPin for an unconfigured node: got nil error, want non-nil")
	}
}
