package webui

import (
	"net/http/httptest"
	"testing"
	"testing/fstest"
)

// TestHandlerFor_NoIndexHTMLReturns404NotDirectoryListing guards
// against a real behavior mismatch Copilot's review flagged on PR #18:
// with only a tracked .gitkeep placeholder in dist/ (a fresh clone, no
// npm build yet), http.FileServerFS alone serves a directory listing
// for "/", not the 404 the doc comment on Handler promises.
func TestHandlerFor_NoIndexHTMLReturns404NotDirectoryListing(t *testing.T) {
	fsys := fstest.MapFS{
		".gitkeep": &fstest.MapFile{},
	}
	h := handlerFor(fsys)

	req := httptest.NewRequest("GET", "/ui/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Fatalf("status = %d, want 404 (no index.html present, must not fall back to a directory listing)", rec.Code)
	}
	// http.NotFoundHandler's exact, known plain-text body -- distinct
	// from http.FileServer's rendered HTML directory-listing page, so
	// this confirms the 404 really came from the explicit check, not a
	// listing that happened to come back empty.
	if body := rec.Body.String(); body != "404 page not found\n" {
		t.Fatalf("body = %q, want http.NotFoundHandler's plain 404 body, not a directory listing", body)
	}
}

func TestHandlerFor_RealBuildServesIndexHTML(t *testing.T) {
	fsys := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html>real admin UI</html>")},
	}
	h := handlerFor(fsys)

	req := httptest.NewRequest("GET", "/ui/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "<html>real admin UI</html>" {
		t.Fatalf("body = %q, want the real index.html content", rec.Body.String())
	}
}
