// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"context"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type IDToken coreoidc.IDToken

// IDTokenSource provides a way to get an OIDC ID Token from an OIDC IdP
type IDTokenSource interface {
	// IDToken returns an ID token or an error.
	IDToken(context.Context) (*IDToken, error)
}

type CachingIDTokenSource struct {
	TokenSource oauth2.TokenSource
	OIDP        *coreoidc.Provider

	currentToken   *oauth2.Token
	currentIDToken *IDToken
}

func (s *CachingIDTokenSource) IDToken() (*IDToken, error) {
	newTok, err := s.TokenSource.Token()
	if err != nil {
		return nil, err
	}
	if newTok.AccessToken == s.currentToken.AccessToken {
		return s.currentIDToken, nil
	}

	return nil, nil
}
