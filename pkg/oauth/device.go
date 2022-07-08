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

package oauth

const (
	// DeviceCodeGrantType is the grant type expected in a RFC8628 Device Access Token request.
	// See: https://datatracker.ietf.org/doc/html/rfc8628#section-3.4
	DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// SigstoreDeviceCodeURL specifies the Device Code endpoint for the public good Sigstore service.
	SigstoreDeviceCodeURL = "https://oauth2.sigstore.dev/auth/device/code"

	// SigstoreTokenURL specifies the Token endpoint for the public good Sigstore service.
	SigstoreTokenURL = "https://oauth2.sigstore.dev/auth/device/token"
)
