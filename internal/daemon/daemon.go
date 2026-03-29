// Package daemon provides cross-platform background service support using
// kardianos/service, which integrates with the native service manager on each
// OS (Windows Services, macOS launchd, Linux systemd).
package daemon

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/kardianos/service"

	"github.com/goodtune/dotvault/internal/paths"
)

// program implements service.Interface for kardianos/service.
type program struct {
	runFunc func(ctx context.Context) error
	cancel  context.CancelFunc
	done    chan error
}

func (p *program) Start(s service.Service) error {
	if p.runFunc == nil {
		return fmt.Errorf("daemon: runFunc not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() { p.done <- p.runFunc(ctx) }()
	return nil
}

func (p *program) Stop(s service.Service) error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.done != nil {
		return <-p.done
	}
	return nil
}

func svcConfig(args []string) *service.Config {
	return &service.Config{
		Name:        "dotvault",
		DisplayName: "DotVault",
		Description: "Vault-to-file secret synchronisation daemon",
		Arguments:   args,
	}
}

// Install registers dotvault as an OS-managed background service and starts
// it. args are the CLI flags the service manager should pass when it launches
// the binary (e.g. ["--config", "/path/to/config.yaml"]).
func Install(args []string) error {
	prg := &program{}
	svc, err := service.New(prg, svcConfig(args))
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	if err := svc.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	if err := svc.Start(); err != nil {
		_ = svc.Uninstall() // clean up on failure
		return fmt.Errorf("start service: %w", err)
	}
	return nil
}

// Run executes the daemon via kardianos/service. When launched by the OS
// service manager it integrates with the native lifecycle (SCM on Windows,
// launchd on macOS, systemd on Linux). When run interactively it behaves as
// a foreground process that shuts down on SIGINT/SIGTERM.
func Run(runFunc func(ctx context.Context) error) error {
	prg := &program{runFunc: runFunc}
	svc, err := service.New(prg, svcConfig(nil))
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	return svc.Run()
}

// IsManaged returns true when the process was started by the OS service
// manager rather than interactively from a terminal.
func IsManaged() bool {
	return !service.Interactive()
}

// PIDFilePath returns the conventional filesystem path where a daemon PID
// file may be stored. This package does not create or manage the PID file;
// it is provided for external tooling or supervisors that want a stable
// location.
func PIDFilePath() string {
	return filepath.Join(paths.CacheDir(), "daemon.pid")
}
