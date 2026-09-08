package dockervol

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// eventPattern is the subscription the watcher asks for. The wildcard covers
// every KVv2 event type — write, patch, delete, undelete, destroy,
// metadata-delete — because a volume that learned only about writes would
// keep serving a deleted secret for as long as the subscription stayed up,
// which under the "cache indefinitely" policy is forever.
const eventPattern = "kv-v2/*"

// Pacing constants for the background loops.
const (
	// tokenPoll is how often the watcher re-checks for a token before its
	// first subscription attempt.
	tokenPoll = 2 * time.Second
	// eventDebounce coalesces a burst of events for one volume (an enrolment
	// writing several secrets, say) into a single re-render.
	eventDebounce = 250 * time.Millisecond
	// Reconnect backoff for the subscription, mirroring the sync engine.
	reconnectMin = time.Second
	reconnectMax = 5 * time.Minute
)

// startLoopLocked starts a volume's refresh loop. Caller holds d.mu. With
// initial set the loop renders immediately — the resume-after-restart case,
// where the directory holds whatever the previous daemon last wrote.
func (d *Driver) startLoopLocked(v *volume, initial bool) {
	ctx, cancel := context.WithCancel(d.lifetime())
	v.cancel = cancel
	v.done = make(chan struct{})
	v.nudge = make(chan struct{}, 1)
	go d.runVolume(ctx, v, initial)
}

// stopLoopLocked stops a volume's loop and returns the channel that closes
// once it has exited, or nil if none was running. Caller holds d.mu and must
// not wait on the channel while holding it.
func (d *Driver) stopLoopLocked(v *volume) chan struct{} {
	if v.cancel == nil {
		return nil
	}
	v.cancel()
	v.cancel = nil
	done := v.done
	v.done = nil
	return done
}

// runVolume keeps one volume fresh until ctx is cancelled.
//
// The policy is the whole point of the loop. An event nudge always
// re-renders. A tick re-renders only when events are not driving refreshes
// — Community edition, or an Enterprise subscription that has dropped —
// so on Enterprise with a live subscription a volume is rendered once and
// then only when Vault says something changed.
func (d *Driver) runVolume(ctx context.Context, v *volume, initial bool) {
	defer close(v.done)
	if initial {
		d.refresh(ctx, v)
	}
	ticker := time.NewTicker(v.Spec.TTL)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-v.nudge:
			select {
			case <-time.After(eventDebounce):
			case <-ctx.Done():
				return
			}
			// Drain anything that arrived during the debounce; it is
			// covered by the render about to happen.
			select {
			case <-v.nudge:
			default:
			}
			d.refresh(ctx, v)
		case <-ticker.C:
			if d.eventsDriving() {
				continue
			}
			d.refresh(ctx, v)
		}
	}
}

func (d *Driver) refresh(ctx context.Context, v *volume) {
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	v.opMu.Lock()
	n, err := materialise(ctx, d.store, d.volumePath(v.Name), v.Spec)
	v.opMu.Unlock()
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		// Shutdown or unmount mid-render: not a failure worth recording
		// against a volume that is about to be wiped or resumed.
		return
	}
	d.recordRefresh(v, n, err)
}

// eventsDriving reports whether a live subscription is keeping volumes fresh.
func (d *Driver) eventsDriving() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.edition == editionEnterprise && d.eventsLive
}

func (d *Driver) setEdition(e edition) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.edition = e
}

func (d *Driver) setEvents(live bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.eventsLive = live
	d.eventsErr = ""
	if err != nil {
		d.eventsErr = err.Error()
	}
}

// nudgeAll asks every active volume to re-render. Used when the subscription
// (re)connects: anything may have changed while nothing was listening.
func (d *Driver) nudgeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.volumes {
		if v.cancel != nil {
			nudge(v)
		}
	}
}

func nudge(v *volume) {
	select {
	case v.nudge <- struct{}{}:
	default:
	}
}

// dispatch routes one Vault event to the volumes it concerns.
func (d *Driver) dispatch(evt vault.Event) {
	rel, ok := d.relPath(evt.Path)
	if !ok {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.volumes {
		if v.cancel != nil && v.Spec.Covers(rel) {
			slog.Debug("vault event concerns docker volume", "volume", v.Name, "path", displayPath(rel), "type", evt.EventType)
			nudge(v)
		}
	}
}

// kvOperationSegments are the leading path segments a KVv2 event path can
// carry after its mount. vault.parseEvent strips "data/"; the other
// operations' events name their own segment, and a volume cares about all
// of them equally.
var kvOperationSegments = []string{"data/", "metadata/", "delete/", "undelete/", "destroy/"}

// relPath maps an event's path (mount already stripped) to a path relative
// to the user's subtree, or false if it lies outside it.
func (d *Driver) relPath(p string) (string, bool) {
	for _, seg := range kvOperationSegments {
		if rest, ok := strings.CutPrefix(p, seg); ok {
			p = rest
			break
		}
	}
	rest, ok := strings.CutPrefix(p, d.opts.UserPrefix)
	if !ok {
		return "", false
	}
	clean, err := vaultfs.CleanPath(rest)
	if err != nil || clean == "" {
		return "", false
	}
	return clean, true
}

// runWatcher decides the refresh policy and, on Enterprise, keeps the event
// subscription up for the driver's lifetime.
//
// It waits for a token first: the edition probe is unauthenticated, but the
// subscription is not, and a watcher that learned "Enterprise" with nothing
// to subscribe with would only spin. Until the edition is known every volume
// polls, so nothing is lost by waiting.
func (d *Driver) runWatcher(ctx context.Context) {
	if d.events == nil {
		d.setEdition(editionCommunity)
		return
	}
	if !d.waitForToken(ctx) {
		return
	}

	delay := reconnectMin
	for {
		health, err := d.events.ServerHealth(ctx)
		if err == nil {
			if health.Enterprise {
				d.setEdition(editionEnterprise)
				break
			}
			d.setEdition(editionCommunity)
			slog.Info("docker volumes refresh on their ttl: event subscription requires vault enterprise")
			return
		}
		slog.Warn("could not determine vault edition for docker volume refresh; polling until it answers", "error", err, "retry_in", delay)
		if !sleep(ctx, delay) {
			return
		}
		delay = min(delay*2, reconnectMax)
	}

	delay = reconnectMin
	for {
		if !d.waitForToken(ctx) {
			return
		}
		evCh, errCh, err := d.events.SubscribeEvents(ctx, eventPattern)
		if err != nil {
			d.setEvents(false, err)
			slog.Warn("docker volume event subscription failed; volumes poll until it connects", "error", err, "retry_in", delay)
			if !sleep(ctx, delay) {
				return
			}
			delay = min(delay*2, reconnectMax)
			continue
		}
		delay = reconnectMin
		d.setEvents(true, nil)
		slog.Info("docker volumes subscribed to vault events", "pattern", eventPattern)
		// Anything may have changed while nothing was listening; the
		// first connection is no exception, since a volume mounted before
		// the watcher got here was rendered without one.
		d.nudgeAll()

		err = d.consume(ctx, evCh, errCh)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("event stream closed")
		}
		d.setEvents(false, err)
		slog.Warn("docker volume event subscription lost; volumes poll until it reconnects", "error", err, "retry_in", delay)
		if !sleep(ctx, delay) {
			return
		}
		delay = min(delay*2, reconnectMax)
	}
}

// consume dispatches events until the stream ends, returning the error that
// ended it (nil for a clean close).
func (d *Driver) consume(ctx context.Context, evCh <-chan vault.Event, errCh <-chan error) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-evCh:
			if !ok {
				return nil
			}
			d.dispatch(evt)
		case err, ok := <-errCh:
			if ok && err != nil {
				return err
			}
			if !ok {
				errCh = nil
			}
		}
	}
}

func (d *Driver) waitForToken(ctx context.Context) bool {
	for !d.hasToken() {
		if !sleep(ctx, tokenPoll) {
			return false
		}
	}
	return true
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// resume reconciles the volume dir with the loaded registry at startup:
// volumes the engine still holds mounted get their loop back (rendering
// immediately, since the files date from the previous daemon), and every
// other directory — an unmounted volume's leftovers, or a name no longer
// known — is removed so no secret outlives the container that needed it.
func (d *Driver) resume() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.volumes {
		if len(v.Mounts) > 0 {
			slog.Info("resuming docker volume still mounted by the engine", "volume", v.Name, "mounts", len(v.Mounts))
			d.startLoopLocked(v, true)
		}
	}
	entries, err := os.ReadDir(d.opts.VolumeDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if v, ok := d.volumes[e.Name()]; ok && v.cancel != nil {
			continue
		}
		p := d.volumePath(e.Name())
		if err := os.RemoveAll(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("could not remove stale docker volume directory", "path", p, "error", err)
		}
	}
}

// stopAll stops every loop and waits for them; the directories are left in
// place for the containers that still hold them.
func (d *Driver) stopAll() {
	d.mu.Lock()
	var dones []chan struct{}
	for _, v := range d.volumes {
		if done := d.stopLoopLocked(v); done != nil {
			dones = append(dones, done)
		}
	}
	d.mu.Unlock()
	for _, done := range dones {
		<-done
	}
}
