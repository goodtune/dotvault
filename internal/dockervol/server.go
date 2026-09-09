package dockervol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/goodtune/dotvault/internal/uds"
)

// contentType is the media type the plugin protocol uses on both directions.
const contentType = "application/vnd.docker.plugins.v1.2+json"

// Protocol paths. The engine POSTs JSON to each; a response carries an `Err`
// string that is empty on success.
const (
	pathActivate     = "/Plugin.Activate"
	pathCreate       = "/VolumeDriver.Create"
	pathRemove       = "/VolumeDriver.Remove"
	pathMount        = "/VolumeDriver.Mount"
	pathPath         = "/VolumeDriver.Path"
	pathUnmount      = "/VolumeDriver.Unmount"
	pathGet          = "/VolumeDriver.Get"
	pathList         = "/VolumeDriver.List"
	pathCapabilities = "/VolumeDriver.Capabilities"
)

// maxRequestBody bounds a request the engine sends. The largest legitimate
// body is a create with a long secrets option, well under a kilobyte.
const maxRequestBody = 1 << 20

// Handler returns the HTTP handler implementing the volume plugin protocol.
// Exported so the protocol can be exercised over httptest without a socket.
func (d *Driver) Handler() http.Handler {
	mux := http.NewServeMux()
	handle := func(path string, fn http.HandlerFunc) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			// The protocol is POST-only; every handler gets the check,
			// including the ones that read no body.
			if r.Method != http.MethodPost {
				w.Header().Set("Allow", http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			fn(w, r)
		})
	}
	handle(pathActivate, func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]any{"Implements": []string{"VolumeDriver"}})
	})
	handle(pathCapabilities, func(w http.ResponseWriter, r *http.Request) {
		respond(w, map[string]any{"Capabilities": map[string]string{"Scope": "local"}})
	})
	handle(pathCreate, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string
			Opts map[string]string
		}
		if !decode(w, r, &req) {
			return
		}
		if err := d.Create(req.Name, req.Opts); err != nil {
			fail(w, err)
			return
		}
		respond(w, errResponse{})
	})
	handle(pathRemove, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		if !decode(w, r, &req) {
			return
		}
		if err := d.Remove(req.Name); err != nil {
			fail(w, err)
			return
		}
		respond(w, errResponse{})
	})
	handle(pathMount, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name, ID string }
		if !decode(w, r, &req) {
			return
		}
		mountpoint, err := d.Mount(r.Context(), req.Name, req.ID)
		if err != nil {
			fail(w, err)
			return
		}
		respond(w, map[string]string{"Mountpoint": mountpoint, "Err": ""})
	})
	handle(pathPath, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		if !decode(w, r, &req) {
			return
		}
		mountpoint, err := d.Path(req.Name)
		if err != nil {
			fail(w, err)
			return
		}
		respond(w, map[string]string{"Mountpoint": mountpoint, "Err": ""})
	})
	handle(pathUnmount, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name, ID string }
		if !decode(w, r, &req) {
			return
		}
		if err := d.Unmount(req.Name, req.ID); err != nil {
			fail(w, err)
			return
		}
		respond(w, errResponse{})
	})
	handle(pathGet, func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Name string }
		if !decode(w, r, &req) {
			return
		}
		info, err := d.Get(req.Name)
		if err != nil {
			fail(w, err)
			return
		}
		respond(w, map[string]any{"Volume": info, "Err": ""})
	})
	handle(pathList, func(w http.ResponseWriter, r *http.Request) {
		respond(w, listResponse{Volumes: d.List()})
	})
	return mux
}

type errResponse struct {
	Err string `json:"Err"`
}

type listResponse struct {
	Volumes []VolumeInfo `json:"Volumes"`
	Err     string       `json:"Err"`
}

// decode reads a JSON request body into v. An empty body is accepted (List
// and Capabilities are sent with none by some engines) and decodes to the
// zero value.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		fail(w, fmt.Errorf("read request: %w", err))
		return false
	}
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, v); err != nil {
		fail(w, fmt.Errorf("decode request: %w", err))
		return false
	}
	return true
}

func respond(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", contentType)
	_ = json.NewEncoder(w).Encode(v)
}

// fail reports an error the way the engine's plugin client expects: a
// non-200 status with an `Err` body it surfaces to the user verbatim. The
// message therefore names paths and options, never secret values — nothing
// in this package puts a value in an error.
func fail(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", contentType)
	status := http.StatusInternalServerError
	if errors.Is(err, ErrNotFound) {
		status = http.StatusNotFound
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errResponse{Err: err.Error()})
}

// Run serves the plugin on the configured socket until ctx is cancelled,
// running the refresh policy alongside. It returns ErrUnsupported off Linux
// without side effects.
//
// On return the volume directories are left in place: a container that
// still holds one bind-mounted keeps working on the last rendering, and the
// next daemon resumes refreshing it. Only an unmount or a remove — the
// engine saying the volume is no longer needed — deletes secrets from disk.
func (d *Driver) Run(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return ErrUnsupported
	}
	d.setLifetime(ctx)
	d.mu.Lock()
	d.activated = false
	d.mu.Unlock()

	// systemd socket activation first (Linux; inert elsewhere), exactly as
	// the API socket and the SSH agent do: an inherited fd means systemd
	// bound the socket and keeps it across our restarts, so an engine
	// request landing mid-restart queues in the backlog instead of the
	// engine reporting the plugin unreachable. Claimed before anything
	// else can fail, because cmd/dotvault keeps the fd out of the
	// unclaimed-fd drain on the strength of this Run: whatever goes wrong
	// from here on, the fd must end up served or drained, never held by
	// systemd with nobody accepting — every engine call would hang in the
	// backlog with no timeout of its own.
	//
	// An activation *error* is a refusal, not a fallback: the fd exists
	// but violates an invariant (mode wider than 0600, wrong socket type),
	// and self-binding would both mask the unit misconfiguration and fail
	// anyway, since systemd owns the path. The refused dup is closed and
	// there is no listener to drain, so this is the one failure that does
	// leave the engine's calls queued; it is logged at ERROR naming the
	// unit, the same condition the API socket treats as fatal to the daemon.
	aln, actual, err := activatedDockerListener()
	if err != nil {
		err = fmt.Errorf("dockervol: systemd activation (check dotvault-docker.socket): %w", err)
		slog.Error("docker volume plugin refused the systemd-activated socket; engine calls will queue until the unit is fixed", "error", err)
		d.setServing(false, err)
		return err
	}
	// Any failure between the claim and Serve hands the fd to a drain for
	// the rest of the process, so the engine fails fast (EOF) instead of
	// hanging — see uds.DrainListener.
	drainOnFail := func(err error) error {
		if aln != nil {
			go uds.DrainListener(aln)
		}
		d.setServing(false, err)
		return err
	}

	if err := d.prepareVolumeRoot(); err != nil {
		return drainOnFail(fmt.Errorf("dockervol: %w", err))
	}

	// Bind before touching any volume directory. Under self-bind the bind
	// is what proves this is the only driver on the socket — a second
	// instance that resumed first would rewrite, and prune, the running
	// daemon's volumes and only then discover it had no business being
	// here. Under activation only the service's MainPID inherits the fd,
	// which serves the same purpose.
	var ln net.Listener
	if aln != nil {
		if actual != d.opts.SocketPath {
			// The socket unit's ListenStream=, not docker.socket, decides
			// where the socket lives under activation. Adopt it so status
			// reports the socket that actually exists — and the operator's
			// .spec file must name this path, not the configured one.
			slog.Warn("systemd-activated docker plugin socket path differs from docker.socket; the socket unit wins", "activated", actual, "configured", d.opts.SocketPath)
		}
		// Under d.mu: Status reads both concurrently.
		d.mu.Lock()
		d.opts.SocketPath = actual
		d.activated = true
		d.mu.Unlock()
		ln = aln
		slog.Info("serving docker volume plugin from systemd activation", "socket", actual, "volume_dir", d.opts.VolumeDir)
	} else {
		ln, err = uds.Listen(d.opts.SocketPath)
		if err != nil {
			if errors.Is(err, uds.ErrAlreadyListening) {
				err = fmt.Errorf("dotvault docker volume plugin already running at %s", d.opts.SocketPath)
			} else {
				err = fmt.Errorf("dockervol: listen: %w", err)
			}
			d.setServing(false, err)
			return err
		}
		slog.Info("docker volume plugin listening", "socket", d.opts.SocketPath, "volume_dir", d.opts.VolumeDir)
	}
	d.setServing(true, nil)
	d.resume()

	srv := &http.Server{
		Handler:           d.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go d.runWatcher(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	err = srv.Serve(ln)
	d.stopAll()
	// A systemd-activated node belongs to the socket unit, which keeps
	// serving it across our restarts; unlinking it would leave systemd
	// listening on an inode no client can reach.
	d.mu.Lock()
	activated, socketPath := d.activated, d.opts.SocketPath
	d.mu.Unlock()
	if !activated {
		uds.Cleanup(socketPath)
	}
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	d.setServing(false, err)
	return err
}

// ActivationName is the FileDescriptorName= the packaged
// dotvault-docker.socket unit sets, by which the daemon claims the inherited
// fd — and which cmd/dotvault must keep out of the unclaimed-fd drain when
// the plugin is enabled.
const ActivationName = "docker"

// DrainActivated claims the systemd-activated plugin socket, if one was
// passed, and drains it for the rest of the process. cmd/dotvault calls it
// when the plugin is enabled — so the fd was kept out of the unclaimed
// drain — but the driver could not be built at all, which would otherwise
// leave every engine call hanging in systemd's backlog.
func DrainActivated() {
	ln, _, err := activatedDockerListener()
	if err != nil {
		slog.Error("docker volume plugin refused the systemd-activated socket; engine calls will queue until the unit is fixed", "error", err)
		return
	}
	if ln != nil {
		slog.Warn("docker volume plugin not started; draining its systemd-activated socket so engine calls fail fast")
		go uds.DrainListener(ln)
	}
}

// activatedDockerListener claims the systemd-activated "docker" socket, when
// one exists. An injectable var (matching internal/web's
// activatedAPIListener) so tests can exercise the activated branch of Run
// without a real systemd environment — the activation snapshot is
// process-global and once-guarded, which makes it unfakeable in-process.
var activatedDockerListener = func() (net.Listener, string, error) {
	return uds.ActivatedListener(ActivationName)
}

// queryTimeout bounds the whole status query, dial and reply alike, for the
// same reason agent.QueryListening bounds its own: a socket node can accept
// a connection that nothing is serving.
const queryTimeout = 5 * time.Second

// QueryListening asks a running daemon's plugin socket for its volume list —
// what `dotvault status` reports, so the output reflects the live driver
// rather than a config-derived guess. It never creates the socket.
func QueryListening(ctx context.Context, socket string) ([]VolumeInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://plugin"+pathList, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRequestBody))
	if err != nil {
		return nil, err
	}
	var out listResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode plugin reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK || out.Err != "" {
		return nil, fmt.Errorf("plugin replied %d: %s", resp.StatusCode, out.Err)
	}
	return out.Volumes, nil
}
