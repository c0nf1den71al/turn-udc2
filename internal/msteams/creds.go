// Package msteams fetches TURN credentials from Microsoft Teams' public
// token service using an anonymous visitor flow: a visitor Skype token is
// minted without authentication, then exchanged for time-limited TURN
// credentials on the trap-exp endpoint.
//
// The flow (endpoints, headers, brotli handling) is adapted from
// praetorian-inc/turnt (Apache License 2.0):
// https://github.com/praetorian-inc/turnt
package msteams

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
)

const (
	visitorURL = "https://teams.microsoft.com/api/authsvc/v1.0/authz/visitor"
	tokensURL  = "https://teams.microsoft.com/trap-exp/tokens"

	userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36"
)

// Credentials is a set of TURN credentials issued by Microsoft Teams.
type Credentials struct {
	Realm    string
	Username string
	Password string
	// Expires is the raw "expires" value from the API. Its unit is not
	// documented; ExpiresAt interprets it heuristically.
	Expires int64
	// Fetched records when the credentials were retrieved.
	Fetched time.Time
}

type responseTokens struct {
	SkypeToken string `json:"skypeToken"`
	ExpiresIn  int    `json:"expiresIn"`
	TokenType  string `json:"tokenType"`
}

type authResponse struct {
	Tokens    responseTokens `json:"tokens"`
	Region    string         `json:"region"`
	Partition string         `json:"partition"`
}

type credentialsResponse struct {
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"password"`
	Expires  int64  `json:"expires"`
}

// DefaultServerHost is the Teams TURN relay hostname issued alongside these
// credentials (TURNS on TCP port 443).
const DefaultServerHost = "worldaz-msit.relay.teams.microsoft.com"
const DefaultServerPort = 443

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		DisableCompression: true,
		Proxy:              http.ProxyFromEnvironment,
	},
}

func getSkypeToken() (string, error) {
	req, err := http.NewRequest(http.MethodPost, visitorURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Host", "teams.microsoft.com")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Authorization", "Bearer")
	req.Header.Set("Ms-Teams-Auth-Type", "ExplicitLogin")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("visitor authz request failed with status code %d", resp.StatusCode)
	}

	var authResp authResponse
	if err := json.Unmarshal(body, &authResp); err != nil {
		return "", err
	}
	if authResp.Tokens.SkypeToken == "" {
		return "", fmt.Errorf("skypeToken not found in response")
	}
	return authResp.Tokens.SkypeToken, nil
}

func getCredentials(skypeToken string) (*credentialsResponse, error) {
	req, err := http.NewRequest(http.MethodGet, tokensURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Host", "teams.microsoft.com")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-Skypetoken", skypeToken)
	req.Header.Set("Accept", "application/json, text/javascript")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trap-exp tokens request failed with status code %d", resp.StatusCode)
	}

	var credResp credentialsResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return nil, err
	}
	return &credResp, nil
}

func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// The API returns brotli-compressed bodies regardless of Accept-Encoding.
	if resp.Header.Get("Content-Encoding") == "br" {
		brReader := brotli.NewReader(bytes.NewReader(body))
		body, err = io.ReadAll(brReader)
		if err != nil {
			return nil, err
		}
	}
	return body, nil
}

// Fetch retrieves anonymous TURN credentials from Microsoft Teams.
func Fetch() (*Credentials, error) {
	skypeToken, err := getSkypeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get Skype token: %w", err)
	}

	credResp, err := getCredentials(skypeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	return &Credentials{
		Realm:    credResp.Realm,
		Username: credResp.Username,
		Password: credResp.Password,
		Expires:  credResp.Expires,
		Fetched:  time.Now(),
	}, nil
}

// ExpiresAt interprets the undocumented "expires" field. If it cannot be
// interpreted, ok is false.
func (c *Credentials) ExpiresAt() (time.Time, bool) {
	v := c.Expires
	switch {
	case v > 1e12: // milliseconds since epoch
		return time.UnixMilli(v), true
	case v > 1e9: // seconds since epoch
		return time.Unix(v, 0), true
	case v > 0: // seconds of validity from issue time
		return c.Fetched.Add(time.Duration(v) * time.Second), true
	}
	return time.Time{}, false
}

// UsernameExpiry parses a REST-style TURN username of the form
// "<unix-seconds>:<nonce>" and returns the embedded expiry. ok is false
// when the username does not embed a timestamp.
func (c *Credentials) UsernameExpiry() (time.Time, bool) {
	prefix, _, found := strings.Cut(c.Username, ":")
	if !found {
		return time.Time{}, false
	}
	secs, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || secs < 1e9 {
		return time.Time{}, false
	}
	return time.Unix(secs, 0), true
}
