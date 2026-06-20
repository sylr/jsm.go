package natscontext_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/nats-io/jsm.go/natscontext"
)

func TestAWSConfigNoOIDC(t *testing.T) {
	c, err := natscontext.New("awsnone", false)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	_, err = c.AWSConfig(context.Background())
	if !errors.Is(err, natscontext.ErrNoAWSConfig) {
		t.Fatalf("expected ErrNoAWSConfig with no oidc, got %v", err)
	}
	if c.OIDC() != nil {
		t.Fatalf("expected nil OIDC, got %#v", c.OIDC())
	}
	if c.AWSConfigSteps() != nil {
		t.Fatalf("expected nil steps, got %#v", c.AWSConfigSteps())
	}
}

func TestAWSConfigNilChain(t *testing.T) {
	// oidc present but aws_config absent/null → not configured.
	c, err := natscontext.NewFromBytes([]byte(`{"oidc": {"audience": "nats://callout"}}`))
	if err != nil {
		t.Fatalf("NewFromBytes: %v", err)
	}
	if c.OIDC() == nil || c.OIDC().Audience != "nats://callout" {
		t.Fatalf("expected oidc with audience, got %#v", c.OIDC())
	}

	_, err = c.AWSConfig(context.Background())
	if !errors.Is(err, natscontext.ErrNoAWSConfig) {
		t.Fatalf("expected ErrNoAWSConfig for a nil chain, got %v", err)
	}
	if c.AWSConfigSteps() != nil {
		t.Fatalf("expected nil steps, got %#v", c.AWSConfigSteps())
	}
}

func TestAWSConfigEmptyPresent(t *testing.T) {
	// A present-but-empty array loads the default credential chain
	// rather than erroring, with optFns still applied.
	c, err := natscontext.NewFromBytes([]byte(`{"oidc": {"aws_config": []}}`))
	if err != nil {
		t.Fatalf("NewFromBytes: %v", err)
	}
	if c.AWSConfigSteps() == nil {
		t.Fatalf("expected non-nil empty steps after decoding []")
	}

	cfg, err := c.AWSConfig(context.Background(), config.WithRegion("eu-west-1"))
	if err != nil {
		t.Fatalf("AWSConfig: %v", err)
	}
	if cfg.Region != "eu-west-1" {
		t.Fatalf("expected optFns region to apply, got %q", cfg.Region)
	}

	// The empty (non-nil) chain must survive a save cycle: with
	// omitempty dropped it serializes as [] and reloads non-nil, so
	// AWSConfig keeps loading the default chain rather than erroring.
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"aws_config":[]`)) {
		t.Fatalf("expected empty array to persist, got %s", data)
	}
	rc, err := natscontext.NewFromBytes(data)
	if err != nil {
		t.Fatalf("NewFromBytes: %v", err)
	}
	if rc.AWSConfigSteps() == nil {
		t.Fatalf("empty chain did not survive round-trip")
	}
	if _, err := rc.AWSConfig(context.Background(), config.WithRegion("eu-west-1")); err != nil {
		t.Fatalf("AWSConfig after round-trip: %v", err)
	}
}

func TestAWSConfigStaticCredentials(t *testing.T) {
	c, err := natscontext.New("awsstatic", false, natscontext.WithOIDC(natscontext.OIDC{
		AWSConfig: []natscontext.AWSConfigStep{
			{
				Region:          "us-east-1",
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
				SessionToken:    "token",
			},
		},
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	cfg, err := c.AWSConfig(context.Background())
	if err != nil {
		t.Fatalf("AWSConfig: %v", err)
	}
	if cfg.Region != "us-east-1" {
		t.Fatalf("expected region us-east-1, got %q", cfg.Region)
	}

	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	if creds.AccessKeyID != "AKIAEXAMPLE" || creds.SecretAccessKey != "secret" || creds.SessionToken != "token" {
		t.Fatalf("static credentials not propagated: %+v", creds)
	}
}

func TestAWSConfigAssumeRoleChain(t *testing.T) {
	c, err := natscontext.New("awschain", false, natscontext.WithOIDC(natscontext.OIDC{
		AWSConfig: []natscontext.AWSConfigStep{
			{
				Region:          "us-east-1",
				AccessKeyID:     "AKIAEXAMPLE",
				SecretAccessKey: "secret",
			},
			{
				RoleARN:     "arn:aws:iam::111111111111:role/first",
				SessionName: "nats",
				Duration:    "30m",
			},
			{
				Region:      "eu-central-1",
				RoleARN:     "arn:aws:iam::222222222222:role/second",
				SessionName: "nats",
			},
		},
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	cfg, err := c.AWSConfig(context.Background())
	if err != nil {
		t.Fatalf("AWSConfig: %v", err)
	}
	// The final hop overrides the region; building the chain itself
	// performs no STS calls (providers resolve lazily), so we only
	// assert on the config that was assembled.
	if cfg.Region != "eu-central-1" {
		t.Fatalf("expected final region eu-central-1, got %q", cfg.Region)
	}
	if cfg.Credentials == nil {
		t.Fatalf("expected an assume-role credentials provider")
	}
}

func TestAWSConfigInvalidDuration(t *testing.T) {
	c, err := natscontext.New("awsbaddur", false, natscontext.WithOIDC(natscontext.OIDC{
		AWSConfig: []natscontext.AWSConfigStep{
			{
				RoleARN:  "arn:aws:iam::111111111111:role/first",
				Duration: "not-a-duration",
			},
		},
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	_, err = c.AWSConfig(context.Background())
	if err == nil {
		t.Fatalf("expected error for invalid duration")
	}
}

func TestOIDCValidate(t *testing.T) {
	// aud is a valid audience added to cases that are not themselves
	// testing audience validation, so each case isolates its own failure.
	const aud = "nats://callout"

	cases := map[string]natscontext.OIDC{
		// audience
		"missing audience":  {},
		"audience too long": {Audience: strings.Repeat("a", 1001)},
		// awsauth knobs
		"bad signing algorithm":     {Audience: aud, SigningAlgorithm: "HS256"},
		"token duration too low":    {Audience: aud, Duration: "30s"},
		"token duration too high":   {Audience: aud, Duration: "2h"},
		"token duration sub-second": {Audience: aud, Duration: "1500ms"},
		"bad token duration":        {Audience: aud, Duration: "not-a-duration"},
		"negative cache refresh":    {Audience: aud, CacheRefreshBefore: "-5s"},
		"bad cache refresh":         {Audience: aud, CacheRefreshBefore: "nope"},
		// aws_config steps
		"static key without secret": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{AccessKeyID: "AKIAEXAMPLE"}},
		},
		"secret without access key": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{SecretAccessKey: "shh"}},
		},
		"profile on later step": {
			Audience: aud,
			AWSConfig: []natscontext.AWSConfigStep{
				{Profile: "default", Region: "us-east-1"},
				{RoleARN: "arn:x", Profile: "other"},
			},
		},
		"static creds on later step": {
			Audience: aud,
			AWSConfig: []natscontext.AWSConfigStep{
				{Profile: "default", Region: "us-east-1"},
				{RoleARN: "arn:x", AccessKeyID: "AKIA", SecretAccessKey: "s"},
			},
		},
		"bad step duration": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{RoleARN: "arn:x", Duration: "xx"}},
		},
		"negative step duration": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{RoleARN: "arn:x", Duration: "-1s"}},
		},
		"assume-role duration too low": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{RoleARN: "arn:x", Duration: "60s"}},
		},
		"assume-role duration too high": {
			Audience:  aud,
			AWSConfig: []natscontext.AWSConfigStep{{RoleARN: "arn:x", Duration: "13h"}},
		},
	}

	for name, ac := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := natscontext.New("acvalidate", false, natscontext.WithOIDC(ac))
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %q", name)
			}
		})
	}
}

func TestOIDCValidateAccepts(t *testing.T) {
	// A fully-specified, in-range section must pass validation.
	c, err := natscontext.New("acok", false, natscontext.WithOIDC(natscontext.OIDC{
		Audience:           "nats://callout",
		SigningAlgorithm:   "ES384",
		Duration:           "5m",
		CacheRefreshBefore: "10s",
		AWSConfig: []natscontext.AWSConfigStep{
			{Profile: "default", Region: "us-east-1", AccessKeyID: "AKIA", SecretAccessKey: "s", SessionToken: "t"},
			{RoleARN: "arn:aws:iam::111111111111:role/first", SessionName: "nats", Duration: "1h"},
		},
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid oidc section, got %v", err)
	}
}

func TestOIDCParsedAccessors(t *testing.T) {
	c, err := natscontext.New("acparse", false, natscontext.WithOIDC(natscontext.OIDC{
		Audience:           "nats://callout",
		SigningAlgorithm:   "ES384",
		Duration:           "5m",
		CachePath:          "/tmp/tok.jwt",
		CacheRefreshBefore: "10s",
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	ac := c.OIDC()
	if ac == nil {
		t.Fatalf("expected oidc")
	}
	if ac.Audience != "nats://callout" || ac.SigningAlgorithm != "ES384" || ac.CachePath != "/tmp/tok.jwt" {
		t.Fatalf("fields not preserved: %#v", ac)
	}
	if d, err := ac.ParsedDuration(); err != nil || d != 5*time.Minute {
		t.Fatalf("ParsedDuration = %s, %v; want 5m", d, err)
	}
	if d, err := ac.ParsedCacheRefreshBefore(); err != nil || d != 10*time.Second {
		t.Fatalf("ParsedCacheRefreshBefore = %s, %v; want 10s", d, err)
	}
}

func TestOIDCJSONRoundTrip(t *testing.T) {
	c, err := natscontext.New("acjson", false, natscontext.WithOIDC(natscontext.OIDC{
		AWSConfig: []natscontext.AWSConfigStep{
			{Profile: "default", Region: "us-east-1"},
			{RoleARN: "arn:aws:iam::111111111111:role/first", SessionName: "nats"},
		},
		Audience: "nats://callout",
		Duration: "5m",
	}))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(data, []byte(`"oidc"`)) {
		t.Fatalf("expected oidc in serialized form, got %s", data)
	}

	rc, err := natscontext.NewFromBytes(data)
	if err != nil {
		t.Fatalf("NewFromBytes: %v", err)
	}

	ac := rc.OIDC()
	if ac == nil {
		t.Fatalf("oidc lost in round-trip")
	}
	if ac.Audience != "nats://callout" || ac.Duration != "5m" {
		t.Fatalf("oidc fields not preserved: %#v", ac)
	}
	steps := rc.AWSConfigSteps()
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps after round-trip, got %d", len(steps))
	}
	if steps[0].Profile != "default" || steps[0].Region != "us-east-1" {
		t.Fatalf("step 0 not preserved: %+v", steps[0])
	}
	if steps[1].RoleARN != "arn:aws:iam::111111111111:role/first" || steps[1].SessionName != "nats" {
		t.Fatalf("step 1 not preserved: %+v", steps[1])
	}
}

func TestContextWithoutOIDCOmitsField(t *testing.T) {
	// oidc uses omitempty, so a context that never sets it must
	// not carry the field at all.
	c, err := natscontext.New("plain", false, natscontext.WithServerURL("nats://localhost:4222"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(data, []byte("oidc")) {
		t.Fatalf("expected no oidc key, got %s", data)
	}
}
