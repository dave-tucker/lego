// Package mythicbeasts implements a DNS provider for solving the DNS-01
// challenge using mythicbeasts DNS.
package mythicbeasts

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
)

// Documentation about Mythic Beasts's Primary DNS API:
// https://www.mythic-beasts.com/support/api/primary

var mythicBeastsBaseURL = "https://dnsapi.mythic-beasts.com/"

// DNSProvider is an implementation of the ChallengeProvider
// that uses Mythic Beasts DNS API to manage TXT records for a domain.
type DNSProvider struct {
	baseURL   string
	passwords map[string]string
}

// NewDNSProvider returns a DNSProvider instance configured for Mythic Beasts
// Credentials must be passed in the environment variables MYTHICBEASTS_API_PASSWORDS. The format is domain and password pairs separated by whitespace"
func NewDNSProvider() (*DNSProvider, error) {
	passwords := os.Getenv("MYTHICBEASTS_API_PASSWORDS")
	return NewDNSProviderCredentials(passwords)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for Mythic Beasts
func NewDNSProviderCredentials(passwords string) (*DNSProvider, error) {
	if passwords == "" {
		return nil, fmt.Errorf("Mythic Beasts credentials missing")
	}

	passwordMap, err := parsePasswords(passwords)
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		baseURL:   mythicBeastsBaseURL,
		passwords: passwordMap,
	}, nil
}

// splitPasswords splits the whitespace separated domain/password pairs in to a map
func parsePasswords(passwords string) (map[string]string, error) {
	results := make(map[string]string)
	parts := strings.Split(passwords, " ")
	if len(parts)%2 != 0 {
		return results, fmt.Errorf("Error parsing Mythic Beasts API passwords. Uneven number of parts. Please ensure you are using the correct format 'example.com mypassword'")
	}

	for i := 0; i < len(parts); i += 2 {
		results[parts[i]] = parts[i+1]
	}

	return results, nil
}

// extractError extracts an error message from an API response
func extractError(body string) error {
	if strings.HasPrefix(body, "N") {
		parts := strings.Split(string(body), ";")
		if len(parts) != 2 {
			// try splitting on ":" as it's a bit inconsistent in the API
			parts = strings.Split(string(body), ":")
			if len(parts) != 2 {
				return fmt.Errorf("Unknown error")
			}
		}
		return fmt.Errorf(strings.TrimSpace(parts[1]))
	}
	return nil
}

// processRequest processes a request using the provided command template
func (d *DNSProvider) processRequest(cmdTemplate, domain, token, keyAuth string) error {
	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)

	authZone, err := acme.FindZoneByFqdn(acme.ToFqdn(domain), acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Could not determine zone for domain: '%s'. %s", domain, err)
	}

	authZone = acme.UnFqdn(authZone)

	if _, ok := d.passwords[authZone]; !ok {
		return fmt.Errorf("Missing password for the authentiation zone: '%s'", authZone)
	}

	password := d.passwords[authZone]
	command := fmt.Sprintf(cmdTemplate, fqdn, value)
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.PostForm(d.baseURL,
		url.Values{"domain": {authZone}, "password": {password}, "command": {command}})

	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if err := extractError(string(body)); err != nil {
		return fmt.Errorf("Unable to add TXT record for domain: '%s'. %s", domain, err.Error())
	}
	return nil

}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	return d.processRequest("REPLACE %s 3600 TXT %s", domain, token, keyAuth)
}

// Cleanup removes the TXT record matching the specified parameters
func (d *DNSProvider) Cleanup(domain, token, keyAuth string) error {
	return d.processRequest("DELETE %s 3600 TXT %s", domain, token, keyAuth)
}
