#!/usr/bin/env bash
# Real end-to-end smoke test for issue #49's release pipeline
# (.goreleaser.yml): there is no application-level unit-test seam for
# "does a cross-compiled, signed, tagged release actually work" --
# release tooling, not application logic -- so this runs goreleaser's
# own `--snapshot --clean` dry-run mode (no git tag needed, nothing
# published, no network calls to GitHub Releases or the Homebrew tap)
# against the real .goreleaser.yml and asserts on its real output: all 4
# platform archives exist, the one matching this host's own GOOS/GOARCH
# is actually extracted and executed (not just "the file is present"),
# its -version output proves the -X ldflags genuinely fired, the archive
# contains README.md/LICENSE, and checksums.txt verifies against the
# real archive bytes. Signing is deliberately NOT exercised here --
# cosign's keyless flow needs a real GitHub Actions-issued OIDC token,
# unavailable locally and not something to fake; that half is proven for
# real in CI instead, by .github/workflows/release.yml's PR-triggered
# snapshot job (id-token: write).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$repo_root/dist"

pass=0
fail=0

check() {
	local desc="$1" got="$2" want="$3"
	if [[ "$got" == "$want" ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (got: $got, want: $want)"
		fail=$((fail + 1))
	fi
}

check_contains() {
	local desc="$1" haystack="$2" needle="$3"
	if [[ "$haystack" == *"$needle"* ]]; then
		echo "  ok   - $desc"
		pass=$((pass + 1))
	else
		echo "  FAIL - $desc (expected to find: $needle)"
		fail=$((fail + 1))
	fi
}

cleanup() {
	rm -rf "$dist_dir" "$work_dir"
}
trap cleanup EXIT

if ! command -v goreleaser >/dev/null 2>&1; then
	echo "goreleaser is not installed -- required for this check (issue #49)." >&2
	echo "Install it: https://goreleaser.com/install/ (e.g. 'brew install goreleaser' on macOS)." >&2
	exit 1
fi

work_dir="$(mktemp -d)"

echo "==> running the real release pipeline in snapshot mode (no tag, no publish, no signing)"
(cd "$repo_root" && goreleaser release --snapshot --clean --skip=publish,announce,sign,homebrew >"$work_dir/goreleaser.log" 2>&1) \
	|| { echo "goreleaser snapshot build failed; log:" >&2; cat "$work_dir/goreleaser.log" >&2; exit 1; }

echo "==> the 4 expected platform archives actually exist"
for os in linux darwin; do
	for arch in amd64 arm64; do
		archive=$(find "$dist_dir" -maxdepth 1 -name "spidercob-gateway_*_${os}_${arch}.tar.gz" | head -1)
		check "archive exists: ${os}/${arch}" "$([[ -n "$archive" ]] && echo yes || echo no)" "yes"
	done
done

echo "==> a real checksums.txt exists and verifies against the real archive bytes"
check "checksums.txt exists" "$([[ -f "$dist_dir/checksums.txt" ]] && echo yes || echo no)" "yes"
(
	cd "$dist_dir"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum -c checksums.txt >"$work_dir/checksum-verify.log" 2>&1
	else
		shasum -a 256 -c checksums.txt >"$work_dir/checksum-verify.log" 2>&1
	fi
)
checksum_status=$?
check "every archive's checksum matches its real bytes" "$([[ "$checksum_status" -eq 0 ]] && echo yes || echo no)" "yes"
if [[ "$checksum_status" -ne 0 ]]; then
	cat "$work_dir/checksum-verify.log" >&2
fi

echo "==> extracting and actually executing the archive matching this host (proves the binary isn't just present, but real and runnable)"
host_os=$(go env GOOS)
host_arch=$(go env GOARCH)
host_archive=$(find "$dist_dir" -maxdepth 1 -name "spidercob-gateway_*_${host_os}_${host_arch}.tar.gz" | head -1)
if [[ -z "$host_archive" ]]; then
	echo "no archive found for this host's platform (${host_os}/${host_arch}) -- cannot execute it" >&2
	exit 1
fi

extract_dir="$work_dir/extracted"
mkdir -p "$extract_dir"
tar -xzf "$host_archive" -C "$extract_dir"

check "archive contains README.md" "$([[ -f "$extract_dir/README.md" ]] && echo yes || echo no)" "yes"
check "archive contains LICENSE" "$([[ -f "$extract_dir/LICENSE" ]] && echo yes || echo no)" "yes"
check "archive contains the spidercob binary" "$([[ -x "$extract_dir/spidercob" ]] && echo yes || echo no)" "yes"

version_output=$("$extract_dir/spidercob" -version)
check_contains "the real binary's -version output identifies itself" "$version_output" "spidercob"
check_contains "the real binary's -version output does NOT show the plain-go-build default (proves -X ldflags actually fired)" "$version_output" "SNAPSHOT"
if [[ "$version_output" == *"dev (commit none"* ]]; then
	echo "  FAIL - -version output still shows the unbuilt default -- goreleaser's -X ldflags did not take effect: $version_output"
	fail=$((fail + 1))
else
	echo "  ok   - -version output is not the unbuilt default"
	pass=$((pass + 1))
fi

echo
echo "==> ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
	echo "goreleaser log:" >&2
	cat "$work_dir/goreleaser.log" >&2
	exit 1
fi
