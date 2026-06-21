// Copyright 2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package natscontext

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// ErrNoAWSConfig is returned by Context.AWSConfig when the context has
// no oidc.aws_config set — the oidc section is absent, or its aws_config
// field is absent or JSON null. A present-but-empty array
// ("aws_config": []) is distinct: it requests the default AWS credential
// chain rather than this error.
var ErrNoAWSConfig = errors.New("oidc.aws_config not configured")

// These mirror the limits enforced by github.com/sylr/nats-oidc-callout's
// awsauth.Config so an invalid context fails at Validate (save) time rather
// than later at token-source construction.
const (
	// maxAudienceLen is the STS-documented maximum length of an audience value.
	maxAudienceLen = 1000
	// minTokenDuration and maxTokenDuration bound the web-identity token
	// lifetime STS GetWebIdentityToken accepts.
	minTokenDuration = 60 * time.Second
	maxTokenDuration = 3600 * time.Second
	// minAssumeRoleDuration and maxAssumeRoleDuration bound the assumed-role
	// session lifetime STS AssumeRole accepts (the effective maximum is the
	// role's MaxSessionDuration, capped at 12h).
	minAssumeRoleDuration = 900 * time.Second
	maxAssumeRoleDuration = 12 * time.Hour
)

// supportedSigningAlgorithms are the JWT signing algorithms STS accepts for
// GetWebIdentityToken; an empty SigningAlgorithm defaults to RS256.
var supportedSigningAlgorithms = map[string]struct{}{
	"RS256": {},
	"ES384": {},
}

// OIDC holds the client-side configuration for connecting to a NATS
// server protected by an OIDC auth-callout service (see
// github.com/sylr/nats-oidc-callout). The client obtains a short-lived
// OIDC token for its identity and presents it as the NATS connection
// token; the callout verifies it and returns a signed NATS user JWT.
//
// The fields here drive the AWS web-identity token source: the NATS CLI
// uses AWSConfig to build an aws.Config, then feeds it together with the
// remaining fields into the awsauth token source so a fresh STS
// web-identity token is minted on every (re)connect.
//
// natscontext deliberately does not import the awsauth module: it stores
// the configuration and exposes the assembled aws.Config plus typed
// accessors, leaving the caller to wire up the token source.
type OIDC struct {
	// AWSConfig is an assume-role chain folded into a single aws.Config
	// by Context.AWSConfig — the credential source authorized to call STS
	// GetWebIdentityToken. See AWSConfigStep for the per-step semantics.
	// The tag intentionally omits omitempty so the nil/empty distinction
	// survives a save cycle: a nil chain serializes as null (Context.AWSConfig
	// returns ErrNoAWSConfig) and a present-but-empty chain serializes as []
	// (loads the default credential chain).
	AWSConfig []AWSConfigStep `json:"aws_config"`
	// Audience is the token audience requested from STS; it must match an
	// audience the callout service allows.
	Audience string `json:"audience,omitempty"`
	// SigningAlgorithm is the JWT signing algorithm requested from STS
	// ("RS256" or "ES384"); the awsauth default ("RS256") applies when empty.
	SigningAlgorithm string `json:"signing_algorithm,omitempty"`
	// Duration is the requested token lifetime, parsed with
	// time.ParseDuration (for example "5m"); STS allows 60s..3600s.
	Duration string `json:"duration,omitempty"`
	// Cache, when true, enables an on-disk token cache so consecutive CLI
	// invocations reuse a minted token instead of calling STS each time.
	// The cache location is managed (a "cache/tokens" sibling of the
	// context store, keyed by context name); see Context.OIDCTokenCachePath.
	Cache bool `json:"cache,omitempty"`
	// CacheRefreshBefore is how close to expiry a cached token may be
	// before awsauth refreshes it in the background, parsed with
	// time.ParseDuration (for example "10s"). Ignored when Cache is false.
	CacheRefreshBefore string `json:"cache_refresh_before,omitempty"`
}

// AWSConfigStep is one hop in an assume-role chain. The aws_config
// array is folded left to right into a single aws.Config: the first
// step seeds the base configuration (profile, region, or static
// credentials), and every step that names a RoleARN assumes that role
// using the credentials produced by the steps before it. The result
// is the credentials of the final hop.
//
// A minimal single-step config selects a profile or static keys with
// no role assumption at all; a two-step config is the common
// "base creds → assume role" case; longer chains model cross-account
// role hopping.
type AWSConfigStep struct {
	// Profile is a named profile from the shared AWS config/credentials
	// files (~/.aws/config, ~/.aws/credentials) used as the credential
	// source. Only meaningful on the first step.
	Profile string `json:"profile,omitempty"`
	// Region sets the AWS region. When set on a later step it overrides
	// the region carried forward from earlier steps, which is the region
	// the STS AssumeRole call for that step is made in.
	Region string `json:"region,omitempty"`
	// RoleARN is the IAM role to assume for this step. When empty the
	// step only adjusts the base configuration (profile, region, static
	// credentials) and performs no role assumption.
	RoleARN string `json:"role_arn,omitempty"`
	// SessionName is the RoleSessionName attached to the AssumeRole call.
	// Ignored when RoleARN is empty.
	SessionName string `json:"session_name,omitempty"`
	// Duration is the assumed-role session lifetime, parsed with
	// time.ParseDuration (for example "15m" or "1h"). Ignored when
	// RoleARN is empty; the AWS default applies when unset.
	Duration string `json:"duration,omitempty"`
	// AccessKeyID, SecretAccessKey, and SessionToken supply static
	// credentials as the base credential source. Only meaningful on the
	// first step; SecretAccessKey is required when AccessKeyID is set.
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
}

// validate checks the oidc section against the same limits awsauth
// enforces, so a context with unusable settings is rejected at save time
// instead of failing later when the token source is built. It is called
// from Context.Validate.
func (o *OIDC) validate() error {
	if o.Audience == "" {
		return errors.New("oidc: audience is required")
	}
	if len(o.Audience) > maxAudienceLen {
		return fmt.Errorf("oidc: audience must be at most %d characters, got %d", maxAudienceLen, len(o.Audience))
	}
	if o.SigningAlgorithm != "" {
		if _, ok := supportedSigningAlgorithms[o.SigningAlgorithm]; !ok {
			return fmt.Errorf("oidc: unsupported signing_algorithm %q (want RS256 or ES384)", o.SigningAlgorithm)
		}
	}
	if o.Duration != "" {
		d, err := o.ParsedDuration()
		if err != nil {
			return err
		}
		if d < minTokenDuration || d > maxTokenDuration {
			return fmt.Errorf("oidc: duration must be between %s and %s, got %s", minTokenDuration, maxTokenDuration, d)
		}
		if d%time.Second != 0 {
			return fmt.Errorf("oidc: duration must be a whole number of seconds, got %s", d)
		}
	}
	if o.CacheRefreshBefore != "" {
		d, err := o.ParsedCacheRefreshBefore()
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("oidc: cache_refresh_before must not be negative, got %s", d)
		}
	}
	for i, step := range o.AWSConfig {
		if err := step.validate(i); err != nil {
			return err
		}
	}

	return nil
}

// validate checks a single assume-role step. profile and static
// credentials are only honored on the first step (see AWSConfig), so they
// are rejected on later steps rather than silently ignored — a stray
// aws_config[1].profile would otherwise connect with the wrong principal.
// When role_arn is set the step duration must additionally fall in the STS
// AssumeRole window.
func (s AWSConfigStep) validate(i int) error {
	if i > 0 && (s.Profile != "" || s.AccessKeyID != "" || s.SecretAccessKey != "" || s.SessionToken != "") {
		return fmt.Errorf("oidc.aws_config[%d]: profile and static credentials are only valid on the first step", i)
	}
	if s.AccessKeyID != "" && s.SecretAccessKey == "" {
		return fmt.Errorf("oidc.aws_config[%d]: secret_access_key is required when access_key_id is set", i)
	}
	if s.AccessKeyID == "" && (s.SecretAccessKey != "" || s.SessionToken != "") {
		return fmt.Errorf("oidc.aws_config[%d]: secret_access_key/session_token require access_key_id", i)
	}
	if s.Duration != "" {
		d, err := time.ParseDuration(s.Duration)
		if err != nil {
			return fmt.Errorf("oidc.aws_config[%d]: invalid duration %q: %w", i, s.Duration, err)
		}
		if s.RoleARN != "" {
			if d%time.Second != 0 {
				return fmt.Errorf("oidc.aws_config[%d]: duration must be a whole number of seconds, got %s", i, d)
			}
			if d < minAssumeRoleDuration || d > maxAssumeRoleDuration {
				return fmt.Errorf("oidc.aws_config[%d]: duration must be between %s and %s, got %s", i, minAssumeRoleDuration, maxAssumeRoleDuration, d)
			}
		}
	}

	return nil
}

// WithOIDC sets the oidc section. Passing the zero value still records a
// present (non-nil) section; set AWSConfig to a non-nil empty slice to
// attach an empty chain that loads the default AWS credential chain.
func WithOIDC(o OIDC) Option {
	return func(s *settings) {
		s.OIDC = &o
	}
}

// OIDC returns the configured oidc section, or nil when the context has
// none. The returned pointer aliases the context's internal state; treat
// it as read-only.
func (c *Context) OIDC() *OIDC {
	return c.config.OIDC
}

// OIDCTokenCachePath returns the on-disk location where this context's
// OIDC web-identity token is cached, or "" when the context has no oidc
// section or caching is disabled (oidc.cache is false). The cache is a
// "cache/tokens" sibling of the context store, keyed by context name:
//
//	<root>/nats/cache/tokens/<name>.jwt
//
// mirroring ContextPath's <root>/nats/context/<name>.json so a context's
// token cache lives alongside the context itself and is removed by name.
func (c *Context) OIDCTokenCachePath() (string, error) {
	if c.config == nil || c.config.OIDC == nil || !c.config.OIDC.Cache {
		return "", nil
	}
	if err := ValidateName(c.Name); err != nil {
		return "", fmt.Errorf("oidc: cannot derive token cache path: %w", err)
	}
	root, err := defaultRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "nats", "cache", "tokens", c.Name+".jwt"), nil
}

// ParsedDuration returns the requested token lifetime as a time.Duration,
// 0 when unset. A non-empty value that does not parse is an error.
func (o *OIDC) ParsedDuration() (time.Duration, error) {
	if o.Duration == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(o.Duration)
	if err != nil {
		return 0, fmt.Errorf("oidc: invalid duration %q: %w", o.Duration, err)
	}
	return d, nil
}

// ParsedCacheRefreshBefore returns the cache refresh window as a
// time.Duration, 0 when unset. A non-empty value that does not parse is
// an error.
func (o *OIDC) ParsedCacheRefreshBefore() (time.Duration, error) {
	if o.CacheRefreshBefore == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(o.CacheRefreshBefore)
	if err != nil {
		return 0, fmt.Errorf("oidc: invalid cache_refresh_before %q: %w", o.CacheRefreshBefore, err)
	}
	return d, nil
}

// AWSConfigSteps returns the configured assume-role chain, nil when none
// is set (no oidc section, or an absent/null aws_config field).
func (c *Context) AWSConfigSteps() []AWSConfigStep {
	if c.config.OIDC == nil {
		return nil
	}
	return c.config.OIDC.AWSConfig
}

// AWSConfig builds an aws.Config from the context's oidc.aws_config
// chain. The first step seeds the base configuration via
// config.LoadDefaultConfig — honoring its profile, region, and static
// credentials — and each step that names a role_arn wraps the running
// credentials in an STS AssumeRole provider, so the chain is applied in
// order and the returned config carries the credentials of the final
// hop. Region set on a later step overrides the region used for that
// hop's AssumeRole call.
//
// The absence of a chain (no oidc section, or a nil aws_config — field
// absent or JSON null) is distinguished from a present-but-empty one:
//
//   - nil chain: AWSConfig returns ErrNoAWSConfig and the zero
//     aws.Config, so callers can tell "not configured" apart from a
//     usable default config.
//   - empty chain ("aws_config": []): the default AWS credential chain
//     is loaded with only the supplied optFns applied, matching a bare
//     config.LoadDefaultConfig call.
//
// The optFns are applied to the initial load before any chain-derived
// options so callers can inject custom HTTP clients, endpoint
// resolvers, or retryers.
//
// Assume-role providers resolve lazily: no STS calls are made by
// AWSConfig itself, only when the returned config's credentials are
// first retrieved.
func (c *Context) AWSConfig(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
	if c.config.OIDC == nil {
		return aws.Config{}, ErrNoAWSConfig
	}

	steps := c.config.OIDC.AWSConfig
	if steps == nil {
		return aws.Config{}, ErrNoAWSConfig
	}
	if len(steps) == 0 {
		cfg, err := config.LoadDefaultConfig(ctx, optFns...)
		if err != nil {
			return aws.Config{}, fmt.Errorf("oidc.aws_config: %w", err)
		}
		return cfg, nil
	}

	base := steps[0]
	loadOpts := append([]func(*config.LoadOptions) error{}, optFns...)
	if base.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(base.Profile))
	}
	if base.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(base.Region))
	}
	if base.AccessKeyID != "" {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(base.AccessKeyID, base.SecretAccessKey, base.SessionToken)))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("oidc.aws_config: %w", err)
	}

	for i, step := range steps {
		if step.Region != "" {
			cfg.Region = step.Region
		}
		if step.RoleARN == "" {
			continue
		}

		var duration time.Duration
		if step.Duration != "" {
			duration, err = time.ParseDuration(step.Duration)
			if err != nil {
				return aws.Config{}, fmt.Errorf("oidc.aws_config[%d]: invalid duration %q: %w", i, step.Duration, err)
			}
			if duration <= 0 {
				return aws.Config{}, fmt.Errorf("oidc.aws_config[%d]: duration must be positive, got %s", i, duration)
			}
		}

		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, step.RoleARN, func(o *stscreds.AssumeRoleOptions) {
			if step.SessionName != "" {
				o.RoleSessionName = step.SessionName
			}
			if duration > 0 {
				o.Duration = duration
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}

	return cfg, nil
}
