package mythicbeasts

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

var fakePasswords = "example.com password123"

func TestParsePasswords(t *testing.T) {
	shortList := "example.com"
	goodList := "example.com 1234 contoso.com password"

	if _, err := parsePasswords(shortList); err == nil {
		t.Fatalf("Expected a list with non-even number of entries to produce an error")
	}

	passwords, err := parsePasswords(goodList)
	if err != nil {
		t.Fatalf("Unable to parse passwords. %s", err)
	}

	if passwords["example.com"] != "1234" {
		t.Fatalf("Expected '1234'. Got '%s'", passwords["example.com"])
	}

	if passwords["contoso.com"] != "password" {
		t.Fatalf("Expected 'password'. Got '%s'", passwords["contoso.com"])
	}

}

func TestExtractError(t *testing.T) {
	body := "NADD www 86400 A 93.93.130.49; Can't have multiple identical records"
	err := extractError(body)
	if err == nil {
		t.Fatalf("Expected an error")
	}
	if err.Error() != "Can't have multiple identical records" {
		t.Fatalf("Expected: 'Can't have multiple identical records', Got: '%s'", err.Error())
	}

	body = "NDELETE www 86400 A 93.93.130.49: No such record"
	err = extractError(body)
	if err == nil {
		t.Fatalf("Expected an error")
	}
	if err.Error() != "No such record" {
		t.Fatalf("Expected: 'No such record', Got: '%s'", err.Error())
	}

	body = "ADD www 86400 A 93.93.130.49"
	if err := extractError(body); err != nil {
		t.Fatalf("Unexpected Error!")
	}
}

func TestMythicBeastsPresent(t *testing.T) {
	var requestReceived bool

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true

		if got, want := r.Method, "POST"; got != want {
			t.Errorf("Expected method to be '%s' but got '%s'", want, got)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Expected Content-Type to be '%s' but got '%s'", want, got)
		}

		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading request body: %v", err)
		}

		if got, want := string(reqBody), `command=REPLACE+_acme-challenge.example.com.+3600+TXT+w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI&domain=example.com&password=password123`; got != want {
			t.Errorf("Expected body data to be: `%s` but got `%s`", want, got)
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, string(reqBody))
	}))
	defer mock.Close()
	mythicBeastsBaseURL = mock.URL

	mbprov, err := NewDNSProviderCredentials(fakePasswords)
	if mbprov == nil {
		t.Fatal("Expected non-nil Mythic Beasts provider, but was nil")
	}
	if err != nil {
		t.Fatalf("Expected no error creating provider, but got: %v", err)
	}

	err = mbprov.Present("example.com", "", "foobar")
	if err != nil {
		t.Fatalf("Expected no error creating TXT record, but got: %v", err)
	}
	if !requestReceived {
		t.Error("Expected request to be received by mock backend, but it wasn't")
	}
}

func TestMythicBeastsCleanup(t *testing.T) {
	var requestReceived bool

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true

		if got, want := r.Method, "POST"; got != want {
			t.Errorf("Expected method to be '%s' but got '%s'", want, got)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Expected Content-Type to be '%s' but got '%s'", want, got)
		}

		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading request body: %v", err)
		}

		if got, want := string(reqBody), `command=DELETE+_acme-challenge.example.com.+3600+TXT+w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI&domain=example.com&password=password123`; got != want {
			t.Errorf("Expected body data to be: `%s` but got `%s`", want, got)
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, string(reqBody))
	}))
	defer mock.Close()
	mythicBeastsBaseURL = mock.URL

	mbprov, err := NewDNSProviderCredentials(fakePasswords)
	if mbprov == nil {
		t.Fatal("Expected non-nil Mythic Beasts provider, but was nil")
	}
	if err != nil {
		t.Fatalf("Expected no error creating provider, but got: %v", err)
	}

	err = mbprov.Cleanup("example.com", "", "foobar")
	if err != nil {
		t.Fatalf("Expected no error creating TXT record, but got: %v", err)
	}
	if !requestReceived {
		t.Error("Expected request to be received by mock backend, but it wasn't")
	}
}
