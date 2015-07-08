/*
Copyright 2015 The Kubernetes Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// openid implements the authenticator.Token interface using the OpenID protocol.
package openid

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/user"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/key"
	"github.com/coreos/go-oidc/oidc"
)

type openIDProvider struct {
	mux     *http.ServeMux
	pcfg    oidc.ProviderConfig
	privKey *key.PrivateKey
}

func newOpenIDProvider(t *testing.T) *openIDProvider {
	privKey, err := key.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Cannot create OpenID Provider: %v", err)
		return nil
	}

	op := &openIDProvider{
		mux:     http.NewServeMux(),
		privKey: privKey,
	}

	op.mux.HandleFunc("/.well-known/openid-configuration", op.handleConfig)
	op.mux.HandleFunc("/keys", op.handleKeys)

	return op

}

func (op *openIDProvider) handleConfig(w http.ResponseWriter, req *http.Request) {
	b, err := json.Marshal(op.pcfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (op *openIDProvider) handleKeys(w http.ResponseWriter, req *http.Request) {
	keys := struct {
		Keys []jose.JWK `json:"keys"`
	}{
		Keys: []jose.JWK{op.privKey.JWK()},
	}

	b, err := json.Marshal(keys)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", int(time.Hour.Seconds())))
	w.Header().Set("Expires", time.Now().Add(time.Hour).Format(time.RFC1123))
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func (op *openIDProvider) generateToken(t *testing.T, name, iss, sub, aud string, iat, exp time.Time) string {
	signer := op.privKey.Signer()
	claims := oidc.NewClaims(iss, sub, aud, iat, exp)
	claims.Add("name", name)

	jwt, err := jose.NewSignedJWT(claims, signer)
	if err != nil {
		t.Fatalf("Cannot generate token: %v", err)
		return ""
	}
	return jwt.Encode()
}

func TestOpenIDDiscoveryTimeout(t *testing.T) {
	maxRetries = 3
	retryBackoff = time.Second

	if _, err := NewOpenID("client-foo", "foo/bar"); err == nil {
		t.Errorf("Expecting error, but got nil")
	}
}

func TestOpenIDDiscoveryNoKeyEndpoint(t *testing.T) {
	op := newOpenIDProvider(t)
	srv := httptest.NewServer(op.mux)
	defer srv.Close()

	op.pcfg = oidc.ProviderConfig{
		Issuer: srv.URL,
	}

	_, err := NewOpenID("client-foo", srv.URL)
	if err != errNoKeyEndpoint {
		t.Errorf("Expecting %v, but got %v", errNoKeyEndpoint, err)
	}
}

func TestOpenIDAuthentication(t *testing.T) {
	op := newOpenIDProvider(t)
	srv := httptest.NewServer(op.mux)
	defer srv.Close()

	op.pcfg = oidc.ProviderConfig{
		Issuer:       srv.URL,
		KeysEndpoint: srv.URL + "/keys",
	}

	openID, err := NewOpenID("client-foo", srv.URL)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	tests := []struct {
		token    string
		userInfo user.Info
		verified bool
		err      string
	}{
		{
			generateGoodToken(t, op, "client-foo", srv.URL),
			&user.DefaultInfo{Name: "client-foo"},
			true,
			"",
		},
		{
			generateMalformedToken(t, op, "client-foo", srv.URL),
			nil,
			false,
			"malformed JWS, unable to decode signature",
		},
		{
			generateGoodToken(t, op, "client-bar", srv.URL), // Invalid 'aud'.
			nil,
			false,
			"oidc: JWT claims invalid: invalid claim value: 'aud'",
		},
		{
			generateGoodToken(t, op, "client-foo", "http://foo-bar.com"), // Invalid issuer.
			nil,
			false,
			"oidc: JWT claims invalid: invalid claim value: 'iss'.",
		},
		{
			generateExpiredToken(t, op, "client-foo", srv.URL),
			nil,
			false,
			"oidc: JWT claims invalid: token is expired",
		},
	}

	for i, tt := range tests {
		user, result, err := openID.AuthenticateToken(tt.token)
		if tt.err != "" {
			if !strings.HasPrefix(err.Error(), tt.err) {
				t.Errorf("#d: Expecting: %v..., but got: %v", i, tt.err, err)
			}
		} else {
			if err != nil {
				t.Errorf("#d: Expecting: %v, but got: %v", i, tt.err, err)
			}
		}
		if !reflect.DeepEqual(tt.verified, result) {
			t.Errorf("#%d: Expecting: %v, but got: %v", i, tt.verified, result)
		}
		if !reflect.DeepEqual(tt.userInfo, user) {
			t.Errorf("#%d: Expecting: %v, but got: %v", i, tt.userInfo, user)
		}
	}
}

func generateGoodToken(t *testing.T, op *openIDProvider, name, issuer string) string {
	return op.generateToken(t, name, issuer, name, name, time.Now(), time.Now().Add(time.Hour))
}

func generateMalformedToken(t *testing.T, op *openIDProvider, name, issuer string) string {
	return op.generateToken(t, name, issuer, name, name, time.Now(), time.Now().Add(time.Hour)) + "randombits"
}

func generateExpiredToken(t *testing.T, op *openIDProvider, name, issuer string) string {
	return op.generateToken(t, name, issuer, name, name, time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))
}
