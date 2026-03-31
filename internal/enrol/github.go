package enrol

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/cli/oauth"
)

const (
	// githubDefaultClientID is the GitHub CLI's public OAuth app client ID.
	githubDefaultClientID = "178c6fc778ccc68e1d6a"
	githubDefaultHost     = "https://github.com"
)

var githubDefaultScopes = []string{"repo", "read:org", "gist"}

// GitHubEngine performs a GitHub OAuth device flow.
type GitHubEngine struct{}

func (e *GitHubEngine) Name() string { return "GitHub" }

func (e *GitHubEngine) Fields() []string { return []string{"oauth_token", "user"} }

func (e *GitHubEngine) Run(ctx context.Context, settings map[string]any, io IO) (map[string]string, error) {
	clientID := githubDefaultClientID
	if v, ok := settings["client_id"].(string); ok && v != "" {
		clientID = v
	}

	hostURL := githubDefaultHost
	if v, ok := settings["host"].(string); ok && v != "" {
		hostURL = "https://" + v
	}

	scopes := githubDefaultScopes
	if raw, ok := settings["scopes"]; ok {
		if sl, ok := raw.([]any); ok {
			scopes = make([]string, 0, len(sl))
			for _, s := range sl {
				if str, ok := s.(string); ok {
					scopes = append(scopes, str)
				}
			}
		}
	}

	host, err := oauth.NewGitHubHost(hostURL)
	if err != nil {
		return nil, fmt.Errorf("parse github host: %w", err)
	}

	flow := &oauth.Flow{
		Host:     host,
		ClientID: clientID,
		Scopes:   scopes,
		Stdout:   io.Out,
		Stdin:    os.Stdin,
		DisplayCode: func(userCode, verificationURI string) error {
			copyToClipboard(userCode)
			fmt.Fprintf(io.Out, "! First, copy your one-time code: %s\n", userCode)
			fmt.Fprintf(io.Out, "- Press Enter to open %s in your browser... ", verificationURI)
			bufio.NewScanner(os.Stdin).Scan()
			return nil
		},
		BrowseURL: func(url string) error {
			fmt.Fprintf(io.Out, "✓ Opened %s in browser\n", url)
			if io.Browser != nil {
				if err := io.Browser(url); err != nil {
					fmt.Fprintf(io.Out, "  (could not open browser automatically: %v)\n", err)
				}
			}
			return nil
		},
	}

	type result struct {
		token string
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		fmt.Fprintf(io.Out, "⠼ Waiting for authentication...\n")
		tok, err := flow.DeviceFlow()
		if err != nil {
			ch <- result{"", err}
			return
		}
		ch <- result{tok.Token, nil}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("device flow: %w", r.err)
		}
		user, err := fetchGitHubUser(ctx, hostURL, r.token)
		if err != nil {
			io.Log.Warn("could not fetch github username", "error", err)
			user = ""
		}
		return map[string]string{
			"oauth_token": r.token,
			"user":        user,
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func fetchGitHubUser(ctx context.Context, hostURL, token string) (string, error) {
	apiURL := hostURL
	if hostURL == githubDefaultHost {
		apiURL = "https://api.github.com"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github api status %d", resp.StatusCode)
	}

	var data struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Login, nil
}
