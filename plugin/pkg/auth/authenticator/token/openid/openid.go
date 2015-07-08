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
	"fmt"
	"net/http"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/user"
	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/golang/glog"
)

var (
	maxRetries   = 5
	retryBackoff = time.Second * 3
)

var errNoKeyEndpoint = fmt.Errorf("OpenID provider must provide 'jwks_uri' for public key discovery")

type OpenIDAuthenticator struct {
	client *oidc.Client
}

// NewOpenID creates a new OpenID client with the given clientID and discovery URL.
// NOTE(yifan): For now we assume the server provides the "jwks_uri" so we don't
// need to manager the key sets by ourselves.
func NewOpenID(clientID, discovery string) (*OpenIDAuthenticator, error) {
	var cfg oidc.ProviderConfig
	var err error

	for i := 0; i <= maxRetries; i++ {
		if i == maxRetries {
			return nil, fmt.Errorf("Failed to fetch provider config after %v retries", maxRetries)
		}

		cfg, err = oidc.FetchProviderConfig(http.DefaultClient, discovery)
		if err == nil {
			break
		}
		glog.Errorf("Failed to fetch provider config, trying again in %v: %v", retryBackoff, err)
		time.Sleep(retryBackoff)
	}

	glog.Infof("Fetched provider config from %s: %#v", discovery, cfg)

	if cfg.KeysEndpoint == "" {
		return nil, errNoKeyEndpoint
	}

	ccfg := oidc.ClientConfig{
		Credentials:    oidc.ClientCredentials{ID: clientID},
		ProviderConfig: cfg,
	}

	client, err := oidc.NewClient(ccfg)
	if err != nil {
		return nil, err
	}
	client.SyncProviderConfig(discovery)

	return &OpenIDAuthenticator{client}, nil
}

// AuthenticateToken decodes and verifies a JWT using the OpenID client, then it will extract the user info
// from the JWT claims.
func (a *OpenIDAuthenticator) AuthenticateToken(value string) (user.Info, bool, error) {
	jwt, err := jose.ParseJWT(value)
	if err != nil {
		return nil, false, err
	}

	if err := a.client.VerifyJWT(jwt); err != nil {
		return nil, false, err
	}

	claims, err := jwt.Claims()
	if err != nil {
		return nil, false, err
	}

	name, ok, err := claims.StringClaim("name")
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, fmt.Errorf("cannot find user name in JWT claims")
	}

	// TODO(yifan): Add UID and Group.
	info := &user.DefaultInfo{
		Name: name,
	}
	return info, true, nil
}
