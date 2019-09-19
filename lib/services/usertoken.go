/*
Copyright 2019 Gravitational, Inc.

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

package services

import (
	"fmt"
	"time"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
)

// UserToken represents a temporary token used to create and reset a user
type UserToken interface {
	// Resource provides common resource properties
	Resource
	// GetUser returns User
	GetUser() string
	// GetType returns Type
	GetType() string
	// GetHOTP returns HOTP
	GetHOTP() []byte
	// GetQRCode returns QRCode
	GetQRCode() []byte
	// GetCreated returns Created
	GetCreated() time.Time
	// GetURL returns URL
	GetURL() string
	// CheckAndSetDefaults checks and set default values for any missing fields.
	CheckAndSetDefaults() error
}

// CreateUserInviteRequest is a request to generate a new user invite token.
type CreateUserInviteRequest struct {
	// Name is the new user name.
	Name string `json:"name"`
	// Roles is the new user roles.
	Roles []string `json:"roles"`
	// TTL specifies how long the generated invite token is valid for.
	TTL time.Duration `json:"ttl"`
}

// Check validates the request.
func (r *CreateUserInviteRequest) Check() error {
	if err := checkUserName(r.Name); err != nil {
		return trace.Wrap(err)
	}
	if len(r.Roles) == 0 {
		return trace.BadParameter("role list can't be empty")
	}
	if r.TTL < 0 {
		return trace.BadParameter("ttl can't be negative")
	}
	return nil
}

// CheckUserToken returns nil if the value is correct, error otherwise
func CheckUserToken(s string) error {
	switch s {
	case UserTokenTypeInvite, UserTokenTypeReset:
		return nil
	}
	return trace.BadParameter("unsupported token type: %v", s)
}

const (
	// UserTokenTypeInvite adds new user to existing account
	UserTokenTypeInvite = "invite"
	// UserTokenTypeReset resets user credentials
	UserTokenTypeReset = "reset"
)

// UserInvite represents a promise to add user to account
type UserInvite struct {
	// Name is the user of this user
	Name string `json:"name"`
	// CreatedBy is a user who sends the invite
	CreatedBy string `json:"created_by"`
	// Created is a time this user invite has been created
	Created time.Time `json:"created"`
	// Roles are the roles that will be assigned to invited user
	Roles []string `json:"roles"`
	// ExpiresIn sets the token expiry time
	ExpiresIn time.Duration `json:"expires_in"`
}

// CheckAndSetDefaults checks and sets defaults for user invite
func (u *UserInvite) CheckAndSetDefaults() error {
	if err := checkUserName(u.Name); err != nil {
		return trace.Wrap(err)
	}
	if u.CreatedBy == "" {
		return trace.BadParameter("missing CreatedBy")
	}
	if u.Created.IsZero() {
		u.Created = time.Now().UTC()
	}
	if len(u.Roles) == 0 {
		return trace.BadParameter("roles can't be empty")
	}
	return nil
}

// checkUserName validates user name
func checkUserName(name string) error {
	if name == "" {
		return trace.BadParameter("user name cannot be empty")
	}

	return nil
}

// UserTokenV3 is an invite token spec format V3
type UserTokenV3 struct {
	// Kind is a resource kind - always resource.
	Kind string `json:"kind"`

	// SubKind is a resource sub kind
	SubKind string `json:"sub_kind,omitempty"`

	// Version is a resource version.
	Version string `json:"version"`

	// Metadata is metadata about the resource.
	Metadata Metadata `json:"metadata"`

	// Spec is a spec of the invite token
	Spec UserTokenSpecV3 `json:"spec"`
}

// GetName returns Name
func (u *UserTokenV3) GetName() string {
	return u.Metadata.Name
}

// GetUser returns User
func (u *UserTokenV3) GetUser() string {
	return u.Spec.User
}

// GetType returns Type
func (u *UserTokenV3) GetType() string {
	return u.Spec.Type
}

// GetHOTP returns HOTP
func (u *UserTokenV3) GetHOTP() []byte {
	return nil
}

// GetQRCode returns QRCode
func (u *UserTokenV3) GetQRCode() []byte {
	return u.Spec.QRCode
}

// GetCreated returns Created
func (u *UserTokenV3) GetCreated() time.Time {
	return u.Spec.Created
}

// GetURL returns URL
func (u *UserTokenV3) GetURL() string {
	return u.Spec.URL
}

// Expiry returns object expiry setting
func (u *UserTokenV3) Expiry() time.Time {
	return u.Metadata.Expiry()
}

// SetExpiry sets object expiry
func (u *UserTokenV3) SetExpiry(t time.Time) {
	u.Metadata.SetExpiry(t)
}

// SetTTL sets Expires header using current clock
func (u *UserTokenV3) SetTTL(clock clockwork.Clock, ttl time.Duration) {
	u.Metadata.SetTTL(clock, ttl)
}

// GetMetadata returns object metadata
func (u *UserTokenV3) GetMetadata() Metadata {
	return u.Metadata
}

// GetVersion returns resource version
func (u *UserTokenV3) GetVersion() string {
	return u.Version
}

// GetKind returns resource kind
func (u *UserTokenV3) GetKind() string {
	return u.Kind
}

// SetName sets the name of the resource
func (u *UserTokenV3) SetName(name string) {
	u.Metadata.Name = name
}

// GetResourceID returns resource ID
func (u *UserTokenV3) GetResourceID() int64 {
	return u.Metadata.ID
}

// SetResourceID sets resource ID
func (u *UserTokenV3) SetResourceID(id int64) {
	u.Metadata.ID = id
}

// GetSubKind returns resource sub kind
func (u *UserTokenV3) GetSubKind() string {
	return u.SubKind
}

// SetSubKind sets resource subkind
func (u *UserTokenV3) SetSubKind(s string) {
	u.SubKind = s
}

// CheckAndSetDefaults checks and set default values for any missing fields.

// CheckAndSetDefaults checks and sets defaults for user invite
func (u UserTokenV3) CheckAndSetDefaults() error {
	return nil
}

// UserTokenSpecV3 is a spec for invite token
type UserTokenSpecV3 struct {
	// User is user name associated with this token
	User string `json:"user"`
	// Type is token type
	Type string `json:"type"`
	// HOTP is a secret value of one time password secret generator
	HOTP []byte `json:"hotp"`
	// QRCode is a QR code value
	QRCode []byte `json:"qr_code"`
	// Created holds information about when the token was created
	Created time.Time `json:"created"`
	// URL is this token URL
	URL string `json:"url"`
}

// NewUserToken returns a new instance of the invite token
func NewUserToken2(token, signupURL string, expires time.Time) *UserTokenV3 {
	tok := UserTokenV3{
		Kind:    KindUserToken,
		Version: V3,
		Metadata: Metadata{
			Name: token,
		},
		Spec: UserTokenSpecV3{
			URL: signupURL,
		},
	}
	if !expires.IsZero() {
		tok.Metadata.SetExpiry(expires)
	}
	return &tok
}

// NewUserToken is a convenience wa to create a RemoteCluster resource.
func NewUserToken(token string) UserTokenV3 {
	return UserTokenV3{
		Kind:    KindUserToken,
		Version: V3,
		Metadata: Metadata{
			Name:      token,
			Namespace: defaults.Namespace,
		},
	}
}

// UserTokenSpecV3Template is a template for V3 UserToken JSON schema
const UserTokenSpecV3Template = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
		"user": {
			"type": ["string"]
		},
		"type": {
			"type": ["string"]
		},
		"hotp": {
			"type": ["string"]
		},
		"qrcode": {
			"type": ["string"]
		},
		"url": {
			"type": ["string"]
		}
  }
}`

// UnmarshalUserToken unmarshals UserToken
func UnmarshalUserToken(bytes []byte) (UserToken, error) {
	if len(bytes) == 0 {
		return nil, trace.BadParameter("missing resource data")
	}

	schema := fmt.Sprintf(V2SchemaTemplate, MetadataSchema, LicenseSpecV3Template, DefaultDefinitions)

	var usertoken UserTokenV3
	err := utils.UnmarshalWithSchema(schema, &usertoken, bytes)
	if err != nil {
		return nil, trace.BadParameter(err.Error())
	}

	return &usertoken, nil
}

// MarshalUserInvite marshals role to JSON or YAML.
func MarshalUserInvite(userinvite UserInvite, opts ...MarshalOption) ([]byte, error) {
	return utils.FastMarshal(userinvite)
}

// MarshalUserToken marshals role to JSON or YAML.
func MarshalUserToken(usertoken UserToken, opts ...MarshalOption) ([]byte, error) {
	return utils.FastMarshal(usertoken)
}
