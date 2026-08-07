package authserver

import (
	"context"
	"sync"
	"time"

	"github.com/sumeetgp/spidercob-gateway/internal/store"
)

// denylist is the authserver's revoked-jti check on the hot path: an
// in-memory map, single-process only (design doc §7 -- a shared/Redis
// version is the v1.1 HA item). Every revocation is also persisted to
// store.Store so it survives a restart; hydrate loads that persisted state
// back in on startup.
type denylist struct {
	mu    sync.RWMutex
	store store.Store
	jtis  map[string]time.Time // jti -> expiresAt
}

func newDenylist(s store.Store) *denylist {
	return &denylist{store: s, jtis: make(map[string]time.Time)}
}

// hydrate loads every not-yet-expired revocation from the store into
// memory. Call once at startup, before serving any requests.
func (d *denylist) hydrate(ctx context.Context) error {
	revs, err := d.store.LoadRevocations(ctx)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range revs {
		d.jtis[r.JTI] = r.ExpiresAt
	}
	return nil
}

// revoke denylists jti immediately in memory and persists it so the
// revocation survives a restart. expiresAt should be the token's own exp --
// there's no reason to keep a revocation past the point the token would
// have stopped validating anyway.
func (d *denylist) revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	d.mu.Lock()
	d.jtis[jti] = expiresAt
	d.mu.Unlock()
	return d.store.RevokeJTI(ctx, jti, expiresAt)
}

func (d *denylist) isRevoked(jti string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, revoked := d.jtis[jti]
	return revoked
}

// tryConsume atomically checks-and-marks jti as used, closing the TOCTOU
// gap a separate isRevoked-then-revoke pair would leave -- two concurrent
// redemptions of the same one-time-use assertion (issue #5, ID-JAG jti
// enforcement) must not both be able to observe "not yet used." Returns
// fresh=true if this call is the one that claimed jti; fresh=false means
// it was already consumed (a replay) and the caller must reject.
func (d *denylist) tryConsume(ctx context.Context, jti string, expiresAt time.Time) (fresh bool, err error) {
	d.mu.Lock()
	if _, already := d.jtis[jti]; already {
		d.mu.Unlock()
		return false, nil
	}
	d.jtis[jti] = expiresAt
	d.mu.Unlock()
	if err := d.store.RevokeJTI(ctx, jti, expiresAt); err != nil {
		return true, err
	}
	return true, nil
}
