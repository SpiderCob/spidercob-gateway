package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
)

// inProcessUpstreamSession is a node's per-session upstream backed by an
// in-process http.Handler instead of a real network upstream (issue #59:
// spidercob-admin, and generically reusable for any future in-process
// node). ServeHTTP calls the wrapped handler directly -- no client.Do,
// no TCP, no subprocess. Session-ID substitution mirrors
// httpUpstreamSession's exactly: the upstream's own (here, whatever the
// wrapped handler internally mints -- for spidercob-admin, the go-sdk's
// StreamableHTTPHandler) session ID never reaches the client, and the
// gateway's own minted ID never reaches the handler.
type inProcessUpstreamSession struct {
	handler http.Handler

	mu                sync.Mutex
	upstreamSessionID string
}

// roundTrip mirrors httpUpstreamSession.roundTrip's shape exactly (same
// method signature, so this type also satisfies streamingRoundTripper
// for free) -- the only real difference is *how* the round trip happens:
// httptest.NewRecorder() + a direct ServeHTTP call instead of a real
// client.Do over the network. rec.Result() returns a genuine, valid
// *http.Response, so every downstream consumer (forward(), the
// streaming path) sees the identical shape a real upstream would
// produce.
func (u *inProcessUpstreamSession) roundTrip(r *http.Request) (*http.Response, error) {
	outReq := r.Clone(r.Context())
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Accept-Encoding") // keep responses uncompressed so they stay scannable, same as httpUpstreamSession

	u.mu.Lock()
	id := u.upstreamSessionID
	u.mu.Unlock()
	if id != "" {
		outReq.Header.Set("Mcp-Session-Id", id)
	} else {
		outReq.Header.Del("Mcp-Session-Id") // never forward the gateway's own minted ID upstream
	}

	rec := httptest.NewRecorder()
	u.handler.ServeHTTP(rec, outReq)
	resp := rec.Result()

	if upstreamID := resp.Header.Get("Mcp-Session-Id"); upstreamID != "" {
		u.mu.Lock()
		u.upstreamSessionID = upstreamID
		u.mu.Unlock()
	}
	return resp, nil
}

func (u *inProcessUpstreamSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp, err := u.roundTrip(r)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer resp.Body.Close()
	writeUpstreamResponse(w, resp)
}

// teardown mirrors httpUpstreamSession.teardown's shape: a synthesized
// DELETE carrying the upstream's own session ID, run through the same
// in-process path rather than a real network request. The URL is a
// placeholder -- http.NewRequestWithContext requires a parseable one,
// but the wrapped handler (a streamable_http MCP server) never inspects
// it, only the method, headers, and body.
func (u *inProcessUpstreamSession) teardown(ctx context.Context) error {
	u.mu.Lock()
	id := u.upstreamSessionID
	u.mu.Unlock()
	if id == "" {
		return nil // upstream never actually established a session of its own
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, "http://in-process.invalid/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Mcp-Session-Id", id)
	rec := httptest.NewRecorder()
	u.handler.ServeHTTP(rec, req)
	return nil
}

// alive is always true, same reasoning as httpUpstreamSession.alive:
// there's no persistent child process on our side to die.
func (u *inProcessUpstreamSession) alive() bool { return true }
