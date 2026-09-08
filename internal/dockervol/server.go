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

	if err := d.prepareVolumeRoot(); err != nil {
		err = fmt.Errorf("dockervol: %w", err)
		d.setServing(false, err)
		return err
	}

	// Bind before touching any volume directory. The bind is what proves
	// this is the only driver on the socket; a second instance that resumed
	// first would rewrite — and prune — the running daemon's volumes and
	// only then discover it had no business being here.
	ln, err := uds.Listen(d.opts.SocketPath)
	if err != nil {
		if errors.Is(err, uds.ErrAlreadyListening) {
			err = fmt.Errorf("dotvault docker volume plugin already running at %s", d.opts.SocketPath)
		} else {
			err = fmt.Errorf("dockervol: listen: %w", err)
		}
		d.setServing(false, err)
		return err
	}
	d.setServing(true, nil)
	slog.Info("docker volume plugin listening", "socket", d.opts.SocketPath, "volume_dir", d.opts.VolumeDir)
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
	uds.Cleanup(d.opts.SocketPath)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	d.setServing(false, err)
	return err
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
