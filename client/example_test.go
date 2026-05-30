package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/goodtune/dotvault/client"
)

// Example shows the typical consumer flow: load dotvault's system config,
// authenticate with the same precedence dotvault uses, then read two known
// per-user fields. Errors are categorised via the exported sentinels.
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

	// Authenticate: VAULT_TOKEN → token file → interactive login.
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

	// Read the two fields rat injects into the agent container.
	ghToken, found, err := cli.ReadUserSecret(ctx, "gh", "oauth_token")
	if err != nil {
		log.Fatalf("read gh token: %v", err)
	}
	if !found {
		log.Fatal("gh oauth_token not enrolled; run `dotvault enrol gh`")
	}

	llKey, _, err := cli.ReadUserSecret(ctx, "litellm", "token")
	if err != nil {
		log.Fatalf("read litellm token: %v", err)
	}

	fmt.Printf("GITHUB_TOKEN and LITELLM_API_KEY resolved (%d + %d bytes)\n",
		len(ghToken), len(llKey))
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
		fmt.Println("run `dotvault login` (or rat will prompt on next run)")
	case errors.Is(err, client.ErrUnreachable):
		fmt.Println("vault is unreachable")
	}
}
