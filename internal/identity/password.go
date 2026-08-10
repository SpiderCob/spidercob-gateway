// Package identity owns local user accounts (Mode A humans) and NHI
// (non-human) agent credentials: CRUD, argon2id hashing for both password
// and agent-secret storage, and credential verification. It knows nothing
// about tokens -- internal/authserver calls into this package to verify
// "who is this," then mints a token itself.
package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters, per OWASP's password-storage cheat sheet minimums
// (m=19MiB, t=2, p=1). Both user passwords and NHI client secrets are
// hashed identically (issue #3, story 21) -- a stolen database shouldn't
// expose either kind of credential.
const (
	argonMemoryKiB = 19 * 1024
	argonTime      = 2
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16
)

// hashSecret returns a self-describing PHC-style string
// ($argon2id$v=19$m=...,t=...,p=...$salt$hash) so verification never needs
// external knowledge of which parameters produced a given hash -- safe to
// change argonMemoryKiB/argonTime/argonThreads later without invalidating
// already-stored hashes.
func hashSecret(plaintext string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

var errMalformedHash = errors.New("identity: malformed hash")

// verifySecret re-derives a hash using the parameters embedded in encoded
// and compares in constant time, so a stolen database's hashing cost can
// change over time without breaking verification of older rows.
func verifySecret(plaintext, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, errMalformedHash
	}
	if version != argon2.Version {
		// A self-describing format that doesn't check its own version tag
		// isn't actually self-describing -- don't silently accept a hash
		// claiming a version this code doesn't actually implement.
		return false, errMalformedHash
	}
	var memory, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &t, &p); err != nil {
		return false, errMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errMalformedHash
	}

	got := argon2.IDKey([]byte(plaintext), salt, t, memory, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
