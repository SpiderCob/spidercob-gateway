package proxy

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/audit"
	"github.com/sumeetgp/spidercob-gateway/internal/metrics"
)

// auditQueueCapacity bounds the in-memory buffer between a request's own
// goroutine and the single background worker that actually persists
// records -- an internal reliability buffer, not an operator-facing
// tuning knob (issue #45 spec's explicit "no new config surface"
// decision), so this stays a fixed constant.
const auditQueueCapacity = 256

// auditWriteTimeout bounds each individual store write runAuditWorker
// performs. store.AppendAuditRecord's SQLite connection already has a 5s
// busy_timeout (internal/store/sqlite.go) -- without a context deadline
// here, a stuck or blocked write could still hang runAuditWorker (and
// therefore Close(), which waits on auditWorkerDone) indefinitely,
// contradicting runAuditWorker's own "Close() can't hang on this" claim.
// 10s gives headroom above the busy_timeout without leaving shutdown
// genuinely unbounded. (Flagged by Copilot's review on PR #46, after
// merge -- fixed here as a direct follow-up.)
const auditWriteTimeout = 10 * time.Second

// AuditRecorder is what the proxy needs to persist a per-MCP-request
// audit record (issue #45) -- a minimal interface mirroring
// TokenValidator's seam so this package doesn't need to import
// internal/store directly. The composition root (cmd/spidercob) adapts
// *store.SQLiteStore's AppendAuditRecord into this shape.
type AuditRecorder interface {
	AppendAuditRecord(ctx context.Context, rec audit.Record) error
}

// SetAuditRecorder wires a sink for per-MCP-request audit records -- the
// composition root calls this once, alongside SetPolicy/SetPinRegistry,
// now that a store exists to back it with. A Gateway with none set (the
// zero value, nil) simply never audits MCP traffic -- enqueueAudit
// no-ops -- the same "start permissive, the composition root opts a real
// backend in once its dependencies exist" posture SetPolicy/
// SetPinRegistry already take, so existing tests and call sites that
// don't need this don't have to construct a store for it.
func (g *Gateway) SetAuditRecorder(a AuditRecorder) {
	g.setAuditRecorder(a, auditQueueCapacity)
}

// setAuditRecorder is SetAuditRecorder's real implementation, taking an
// explicit queue capacity so tests can exercise overflow directly
// against a real queue rather than against a hypothetical one.
//
// SetAuditRecorder's contract is "called once, by the composition root,
// right after New" -- but a second call is made safe rather than left to
// leak: without this, the old runAuditWorker goroutine would block
// forever on channels nothing references anymore (its select reads the
// struct fields, which a second call would have already overwritten),
// and Close() would only ever stop the most recently installed worker,
// silently leaving the first one running (and its queue never drained)
// for the rest of the process's life. So any existing worker is stopped
// and fully exited *before* new channels are created. The new channels
// are also assigned before auditRecorder, deliberately: enqueueAudit's
// nil-check on auditRecorder is what a concurrent caller uses to decide
// the queue is ready, so auditRecorder must never go non-nil first.
// (Flagged by Copilot's review on PR #46, after merge -- fixed here as a
// direct follow-up.)
func (g *Gateway) setAuditRecorder(a AuditRecorder, capacity int) {
	if g.stopAuditWorker != nil {
		close(g.stopAuditWorker)
		<-g.auditWorkerDone
	}
	queue := make(chan audit.Record, capacity)
	stop := make(chan struct{})
	done := make(chan struct{})
	g.auditQueue = queue
	g.stopAuditWorker = stop
	g.auditWorkerDone = done
	g.auditRecorder = a
	go g.runAuditWorker(queue, stop, done)
}

// runAuditWorker is the single consumer draining queue -- the thing that
// keeps hash-chain writes correctly serialized regardless of how many
// request goroutines are enqueuing concurrently (store.AppendAuditRecord's
// read-last-hash-then-insert requires exactly this, whether or not this
// package is the one enforcing it). On shutdown it drains whatever's
// already buffered, bounded by that buffer's size -- it never blocks
// waiting for new sends once shutdown has begun, so Close() can't hang on
// that. queue/stop/done are passed explicitly (not read from the Gateway
// struct on every loop iteration) so this goroutine keeps operating on
// exactly the channels it was started with, even if setAuditRecorder is
// later called again and overwrites those fields with a new set.
func (g *Gateway) runAuditWorker(queue chan audit.Record, stop, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-stop:
			g.drainAuditQueue(queue)
			return
		case rec := <-queue:
			g.writeAuditRecord(rec)
		}
	}
}

func (g *Gateway) drainAuditQueue(queue chan audit.Record) {
	for {
		select {
		case rec := <-queue:
			g.writeAuditRecord(rec)
		default:
			return
		}
	}
}

// writeAuditRecord persists rec with a bounded context (auditWriteTimeout)
// -- never context.Background() -- so a stuck or blocked store write can't
// hang this worker, and therefore can't hang Close() either.
func (g *Gateway) writeAuditRecord(rec audit.Record) {
	ctx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()
	if err := g.auditRecorder.AppendAuditRecord(ctx, rec); err != nil {
		slog.Error("failed to append MCP-request audit record", "action", rec.Action, "resource", rec.Resource, "err", err)
	}
}

// enqueueAudit records one per-MCP-request audit event via a
// non-blocking send to the bounded queue runAuditWorker drains -- so a
// busy gateway's request latency is never at the mercy of the store's
// write-transaction. If the queue is ever full, the record is dropped --
// counted (metrics.AuditRecordsDropped) and logged, never silently --
// and the request itself proceeds completely unaffected, exactly the "a
// store failure here is logged but deliberately never fails the
// request" posture logAdminAction already established for admin actions
// (internal/adminapi/routes.go).
//
// action and resource follow issue #45 spec's fixed encoding, reusing
// audit.Record's existing shape rather than adding new fields:
// action is "<rpc_method>:<outcome>" (e.g. "tools/call:allowed",
// "tools/call:denied_policy"), resource is "<node>" or, for tools/call,
// "<node>/<tool>".
func (g *Gateway) enqueueAudit(claims AuthClaims, action, resource string) {
	if g.auditRecorder == nil {
		return
	}
	nhiSubject, humanUsername := actorFieldsFromClaims(claims)
	rec := audit.Record{
		Timestamp:          time.Now(),
		ActorNHISubject:    nhiSubject,
		ActorHumanUsername: humanUsername,
		Action:             action,
		Resource:           resource,
	}
	select {
	case g.auditQueue <- rec:
	default:
		metrics.AuditRecordsDropped.Inc()
		slog.Warn("audit queue full -- dropping MCP-request audit record", "action", action, "resource", resource)
	}
}

// actorFieldsFromClaims splits an already-authenticated AuthClaims.Subject
// ("user:<username>" or "agent:<client_id>", the same shape
// internal/authserver mints and internal/policy.Evaluator already
// parses this exact way) into audit.Record's two actor fields. No new
// identity lookup -- this only formats data the proxy already has
// post-authentication. ActorHumanRole deliberately stays empty: role is
// an admin-API/spider-snoop concept AuthClaims doesn't carry, unlike an
// admin action's audit record.
func actorFieldsFromClaims(claims AuthClaims) (nhiSubject, humanUsername string) {
	switch {
	case strings.HasPrefix(claims.Subject, "agent:"):
		return claims.Subject, ""
	case strings.HasPrefix(claims.Subject, "user:"):
		return "", strings.TrimPrefix(claims.Subject, "user:")
	default:
		return "", ""
	}
}

// auditResource formats audit.Record's Resource field for an MCP
// request: just the node for a node-level method, "<node>/<tool>" for
// tools/call.
func auditResource(nodeName, toolName string) string {
	if toolName == "" {
		return nodeName
	}
	return nodeName + "/" + toolName
}
