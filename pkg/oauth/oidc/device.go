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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauth/internal"
)

type deviceCodeResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type tokenResp struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

// DeviceFlowTokenGetter fetches an OIDC Identity token using the Device Code Grant flow as specified in RFC8628
type deviceIDTokenSource struct {
	messagePrinter func(string)
	sleeper        func(time.Duration)
	issuer         string
	deviceCodeURL  string
	tokenURL       string
	clientID       string
}

// DeviceFlowIDTokenSource creates an IDTokenSource which retrieves an OIDC Identity Token using a Device Code Grant
func DeviceFlowIDTokenSource(issuer, deviceCodeURL, tokenURL, clientID string) IDTokenSource {
	return &deviceIDTokenSource{
		messagePrinter: func(s string) { fmt.Println(s) },
		sleeper:        time.Sleep,
		issuer:         issuer,
		deviceCodeURL:  deviceCodeURL,
		tokenURL:       tokenURL,
		clientID:       clientID,
	}
}

func (idts *deviceIDTokenSource) deviceFlow(ctx context.Context) (*IDToken, error) {
	data := url.Values{
		"client_id": []string{idts.clientID},
		"scope":     []string{"openid", "email"},
	}

	/* #nosec */
	resp, err := http.PostForm(idts.deviceCodeURL, data)
	if err != nil {
		return nil, err
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	parsed := deviceCodeResp{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		return nil, err
	}
	uri := parsed.VerificationURIComplete
	if uri == "" {
		uri = parsed.VerificationURI
	}
	idts.messagePrinter(fmt.Sprintf("Enter the verification code %s in your browser at: %s", parsed.UserCode, uri))
	idts.messagePrinter(fmt.Sprintf("Code will be valid for %d seconds", parsed.ExpiresIn))

	for {
		// Some providers use a secret here, we don't need for sigstore oauth one so leave it off.
		data := url.Values{
			"grant_type":  []string{oauth.DeviceCodeGrantType},
			"device_code": []string{parsed.DeviceCode},
			"scope":       []string{"openid", "email"},
		}

		/* #nosec */
		resp, err := http.PostForm(idts.tokenURL, data)
		if err != nil {
			return nil, err
		}

		token, err := internal.ParseAccessTokenResponse(resp)
		if err != nil {
			return nil, err
		}

		unverifiedIDToken := token.Extra("id_token").(string)

		if unverifiedIDToken != "" {
			idts.messagePrinter("Token received!")
			return unverifiedIDToken, nil
		}
		switch tr.Error {
		case "access_denied", "expired_token":
			return "", fmt.Errorf("error obtaining token: %s", tr.Error)
		case "authorization_pending":
			idts.sleeper(time.Duration(parsed.Interval) * time.Second)
		case "slow_down":
			// Add ten seconds if we got told to slow down
			idts.sleeper(time.Duration(parsed.Interval)*time.Second + 10*time.Second)
		default:
			return nil, fmt.Errorf("unexpected error in device flow: %s", tr.Error)
		}
	}
}

// IDToken gets an OIDC ID Token from the specified provider using the device code grant flow
func (idts *deviceIDTokenSource) IDToken(ctx context.Context) (*IDToken, error) {
	unverifiedIDToken, err := idts.deviceFlow(ctx)
	if err != nil {
		return nil, err
	}
	verifier := p.Verifier(&coreoidc.Config{ClientID: idts.clientID})
	return extractAndVerifyIDToken(ctx, token, verifier, nonce)
}
