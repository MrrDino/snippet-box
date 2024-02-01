package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MrrDino/snippetbox/internal/assert"
)

func TestSecureHeaders(t *testing.T) {

	rr := httptest.NewRecorder()

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	secureHeaders(next).ServeHTTP(rr, r)

	rs := rr.Result()

	exceptedValue := "default-src 'self'; style-src 'self' fonts.googleapis.com; font-src fonts.gstatic.com"
	assert.Equal(t, rs.Header.Get("Content-Security-Policy"), exceptedValue)

	exceptedValue = "origin-when-cross-origin"
	assert.Equal(t, rs.Header.Get("Referrer-Policy"), exceptedValue)

	exceptedValue = "nosniff"
	assert.Equal(t, rs.Header.Get("X-Content-Type-Options"), exceptedValue)

	exceptedValue = "deny"
	assert.Equal(t, rs.Header.Get("X-Frame-Options"), exceptedValue)

	exceptedValue = "0"
	assert.Equal(t, rs.Header.Get("X-XSS-Protection"), exceptedValue)

	assert.Equal(t, rs.StatusCode, http.StatusOK)

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	bytes.TrimSpace(body)

	assert.Equal(t, string(body), "OK")
}
