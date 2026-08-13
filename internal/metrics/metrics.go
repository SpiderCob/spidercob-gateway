// Package metrics is a minimal, dependency-free Prometheus text-format
// exporter. Zero deps keeps the scaffold compiling with no go.sum; swap in
// prometheus/client_golang later if richer types are needed — the call sites
// won't change shape.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

var (
	regMu      sync.Mutex
	collectors []collector
)

type collector interface {
	write(b *strings.Builder)
}

func register(c collector) {
	regMu.Lock()
	collectors = append(collectors, c)
	regMu.Unlock()
}

// --- Counter ---

type Counter struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	vals       map[string]float64
}

func NewCounter(name, help string, labels ...string) *Counter {
	c := &Counter{name: name, help: help, labels: labels, vals: map[string]float64{}}
	register(c)
	return c
}

func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

func (c *Counter) Add(n float64, labelValues ...string) {
	c.mu.Lock()
	c.vals[key(labelValues)] += n
	c.mu.Unlock()
}

// Value returns the counter's current total for the given label values --
// exported for tests that need to assert a counter actually moved (issue
// #45's audit-queue-overflow test), not just that the code path claiming
// to increment it ran.
func (c *Counter) Value(labelValues ...string) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.vals[key(labelValues)]
}

func (c *Counter) write(b *strings.Builder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	for _, k := range sortedKeys(c.vals) {
		b.WriteString(c.name)
		writeLabels(b, labelPairs(c.labels, k))
		fmt.Fprintf(b, " %g\n", c.vals[k])
	}
}

// --- Histogram ---

type Histogram struct {
	name, help string
	labels     []string
	buckets    []float64 // upper bounds, ascending
	mu         sync.Mutex
	data       map[string]*hdata
}

type hdata struct {
	counts []uint64
	sum    float64
	total  uint64
}

func NewHistogram(name, help string, buckets []float64, labels ...string) *Histogram {
	h := &Histogram{name: name, help: help, labels: labels, buckets: buckets, data: map[string]*hdata{}}
	register(h)
	return h
}

func (h *Histogram) Observe(v float64, labelValues ...string) {
	k := key(labelValues)
	h.mu.Lock()
	d, ok := h.data[k]
	if !ok {
		d = &hdata{counts: make([]uint64, len(h.buckets))}
		h.data[k] = d
	}
	for i, ub := range h.buckets {
		if v <= ub {
			d.counts[i]++
		}
	}
	d.sum += v
	d.total++
	h.mu.Unlock()
}

func (h *Histogram) write(b *strings.Builder) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	for _, k := range sortedHKeys(h.data) {
		d := h.data[k]
		pairs := labelPairs(h.labels, k)
		var cum uint64
		for i, ub := range h.buckets {
			cum += d.counts[i]
			bp := append(append([]string{}, pairs...), fmt.Sprintf(`le="%g"`, ub))
			b.WriteString(h.name + "_bucket")
			writeLabels(b, bp)
			fmt.Fprintf(b, " %d\n", cum)
		}
		bp := append(append([]string{}, pairs...), `le="+Inf"`)
		b.WriteString(h.name + "_bucket")
		writeLabels(b, bp)
		fmt.Fprintf(b, " %d\n", d.total)
		b.WriteString(h.name + "_sum")
		writeLabels(b, pairs)
		fmt.Fprintf(b, " %g\n", d.sum)
		b.WriteString(h.name + "_count")
		writeLabels(b, pairs)
		fmt.Fprintf(b, " %d\n", d.total)
	}
}

// --- plumbing ---

const sep = "\xff"

func key(vals []string) string { return strings.Join(vals, sep) }

var escaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func labelPairs(names []string, k string) []string {
	if len(names) == 0 {
		return nil
	}
	vals := strings.Split(k, sep)
	pairs := make([]string, 0, len(names))
	for i, n := range names {
		v := ""
		if i < len(vals) {
			v = vals[i]
		}
		pairs = append(pairs, fmt.Sprintf(`%s="%s"`, n, escaper.Replace(v)))
	}
	return pairs
}

func writeLabels(b *strings.Builder, pairs []string) {
	if len(pairs) == 0 {
		return
	}
	b.WriteString("{" + strings.Join(pairs, ",") + "}")
}

func sortedKeys(m map[string]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

func sortedHKeys(m map[string]*hdata) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// Handler serves all registered metrics in Prometheus text format.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		var b strings.Builder
		regMu.Lock()
		cs := append([]collector(nil), collectors...)
		regMu.Unlock()
		for _, c := range cs {
			c.write(&b)
		}
		_, _ = w.Write([]byte(b.String()))
	})
}

// --- gateway metrics ---

var (
	// Requests counts every request through the data plane.
	Requests = NewCounter("spidercob_requests_total",
		"MCP requests handled by the gateway.", "node", "rpc_method", "code")

	// ScanVerdicts counts non-allow sanitization outcomes. The redact counter
	// is the demo stat: secrets stopped at the boundary.
	ScanVerdicts = NewCounter("spidercob_scan_verdicts_total",
		"Sanitization verdicts by scanner.", "scanner", "action", "direction", "node")

	// UpstreamDuration measures end-to-end proxied request latency.
	UpstreamDuration = NewHistogram("spidercob_upstream_duration_seconds",
		"Latency of proxied MCP requests.",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		"node")

	// AuditRecordsDropped counts per-MCP-request audit records dropped
	// because the async write queue was full (issue #45) -- the signal
	// that distinguishes "quiet gateway" from "audit trail silently
	// losing data" under sustained load.
	AuditRecordsDropped = NewCounter("spidercob_audit_records_dropped_total",
		"Per-MCP-request audit records dropped because the write queue was full.")
)
