package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/goodtune/dotvault/client"
)

// Example shows the typical consumer flow: load dotvault's system config,
// authenticate with the same precedence dotvault uses, then read a known
// per-user field. Errors are categorised via the exported sentinels.
func Example() {
	ctx := context.Background()

	cfg, err := client.LoadConfig(client.DefaultConfigPath())
	if err != nil {
		log.Fatalf("load dotvault config: %v", err)
	}

	cli, err := client.New(cfg)
	if err != nil {
		log.Fatalf("build client: %v", err)
	}

	// Authenticate: DOTVAULT_TOKEN → token file → interactive login.
	if err := cli.Authenticate(ctx); err != nil {
		switch {
		case errors.Is(err, client.ErrUnreachable):
			log.Fatalf("vault unreachable: %v", err)
		case errors.Is(err, client.ErrAuthFailed):
			log.Fatalf("login failed: %v", err)
		default:
			log.Fatalf("authenticate: %v", err)
		}
	}

	// Read a known per-user field, e.g. the oauth_token written by the
	// github enrolment engine. The (value, found, err) triple keeps a
	// not-yet-enrolled secret distinct from a transport failure.
	token, found, err := cli.ReadUserSecret(ctx, "gh", "oauth_token")
	if err != nil {
		log.Fatalf("read secret: %v", err)
	}
	if !found {
		log.Fatal("gh/oauth_token not enrolled; run `dotvault enrol gh`")
	}

	fmt.Printf("resolved oauth_token (%d bytes)\n", len(token))
}

// ExampleClient_AuthenticateCached shows the side-effect-free preflight a
// `doctor` subcommand would use: it never opens a browser or prompts. A
// missing or expired token surfaces as ErrLoginRequired rather than dropping
// the user into a login flow.
func ExampleClient_AuthenticateCached() {
	cfg, err := client.LoadConfig(client.DefaultConfigPath())
	if err != nil {
		log.Fatal(err)
	}
	cli, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	switch err := cli.AuthenticateCached(context.Background()); {
	case err == nil:
		fmt.Println("cached vault token is usable")
	case errors.Is(err, client.ErrLoginRequired):
		fmt.Println("run `dotvault login` (or let Authenticate prompt next run)")
	case errors.Is(err, client.ErrUnreachable):
		fmt.Println("vault is unreachable")
	}
}

// fetchCreds is the kind of helper a consumer would write: it depends on the
// narrow client.Reader interface, never on *client.Client, so it can be unit
// tested against a fake without a live Vault.
func fetchCreds(ctx context.Context, r client.Reader) (string, error) {
	tok, found, err := r.ReadUserSecret(ctx, "gh", "oauth_token")
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("gh/oauth_token not enrolled")
	}
	return tok, nil
}

// fakeReader is a hand-written test double satisfying client.Reader. A
// consumer drops one of these into its own tests; no Vault, no network.
type fakeReader struct {
	identity string
	secrets  map[string]string // "<service>/<field>" -> value
}

func (f fakeReader) IdentityName() (string, error) { return f.identity, nil }

func (f fakeReader) ReadKVField(_ context.Context, _, _, _ string) (string, bool, error) {
	return "", false, nil
}

func (f fakeReader) ReadUserSecret(_ context.Context, service, field string) (string, bool, error) {
	v, ok := f.secrets[service+"/"+field]
	return v, ok, nil
}

// ExampleReader shows how a consumer tests code that reads secrets by
// substituting a fake for the live client — the recommended pattern.
func ExampleReader() {
	r := fakeReader{
		identity: "alice",
		secrets:  map[string]string{"gh/oauth_token": "ghp_fake"},
	}
	tok, err := fetchCreds(context.Background(), r)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok)
	// Output: ghp_fake
}
