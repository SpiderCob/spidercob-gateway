package authserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// keyPair is one Ed25519 signing key, identified by a kid derived from its
// public key (so it's stable and reproducible, not an arbitrary counter).
type keyPair struct {
	kid  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// KeySet holds every signing key the authserver currently trusts for
// verification, plus which one it's actively using to sign new tokens.
// Multiple concurrent keys exist from day one (issue #3, story 9): Rotate
// generates a new active key while every previously-issued key stays in
// the set -- and therefore in JWKS -- until the caller explicitly Retires
// it, which should only happen once every token it ever signed has
// expired. No caller triggers Rotate/Retire yet (no admin API exists
// before Phase 4), but the capability has to exist now -- retrofitting
// multi-key support later, after real tokens are in flight, is the
// expensive order to do this in.
type KeySet struct {
	mu     sync.RWMutex
	keys   map[string]*keyPair
	active string
}

// NewKeySet generates a fresh KeySet with one active signing key.
func NewKeySet() (*KeySet, error) {
	ks := &KeySet{keys: make(map[string]*keyPair)}
	if _, err := ks.Rotate(); err != nil {
		return nil, err
	}
	return ks, nil
}

// Rotate generates a new Ed25519 key and makes it the active signer. Older
// keys remain valid for verification (JWKS keeps publishing them) until
// Retire removes them.
func (ks *KeySet) Rotate() (kid string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 key: %w", err)
	}
	sum := sha256.Sum256(pub)
	kid = base64.RawURLEncoding.EncodeToString(sum[:12])

	ks.mu.Lock()
	ks.keys[kid] = &keyPair{kid: kid, priv: priv, pub: pub}
	ks.active = kid
	ks.mu.Unlock()
	return kid, nil
}

// Retire removes a key from the set entirely -- verification of any token
// still bearing its kid will fail from that point on. Only safe to call
// once every token that key signed has passed its exp.
func (ks *KeySet) Retire(kid string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if kid == ks.active {
		return // never retire the key currently signing new tokens
	}
	delete(ks.keys, kid)
}

func (ks *KeySet) activeKey() *keyPair {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.keys[ks.active]
}

func (ks *KeySet) keyByKID(kid string) (*keyPair, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	kp, ok := ks.keys[kid]
	return kp, ok
}

// sign encodes and signs claims with the active key, stamping its kid and
// the given typ into the JWT header so verification can tell an access
// token from a local-session token (see claims.go) without trusting the
// payload alone.
func (ks *KeySet) sign(claims jwt.Claims, typ string) (string, error) {
	kp := ks.activeKey()
	if kp == nil {
		return "", fmt.Errorf("no active signing key")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kp.kid
	token.Header["typ"] = typ
	return token.SignedString(kp.priv)
}

// jwk is one entry of a JWKS document, RFC 7517 shape for an Ed25519
// (OKP/Ed25519) public key.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwksDocument struct {
	Keys []jwk `json:"keys"`
}

// JWKS returns every currently-trusted public key, in the standard
// /.well-known/jwks.json shape.
func (ks *KeySet) JWKS() jwksDocument {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	doc := jwksDocument{Keys: make([]jwk, 0, len(ks.keys))}
	for _, kp := range ks.keys {
		doc.Keys = append(doc.Keys, jwk{
			Kty: "OKP",
			Crv: "Ed25519",
			Kid: kp.kid,
			X:   base64.RawURLEncoding.EncodeToString(kp.pub),
			Use: "sig",
			Alg: "EdDSA",
		})
	}
	return doc
}
