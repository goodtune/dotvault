package dockervol

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goodtune/dotvault/internal/clientcert"
	"github.com/goodtune/dotvault/internal/vault"
	"github.com/goodtune/dotvault/internal/vaultfs"
)

// eventPattern is the subscription the watcher asks for. The wildcard covers
// every KVv2 event type — write, patch, delete, undelete, destroy,
// metadata-delete — because a volume that learned only about writes would
// keep serving a deleted secret for as long as the subscription stayed up,
// which under the "cache indefinitely" policy is forever.
const eventPattern = "kv-v2/*"

// Pacing for the background loops. Variables rather than constants so a
// test can shorten them; production never writes them.
var (
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
// Otherwise seed is the certificate pair the caller's own render wrote (nil
// for a volume without one), from which the loop schedules the certificate's
// next refresh.
func (d *Driver) startLoopLocked(v *volume, initial bool, seed *clientcert.Pair) {
	ctx, cancel := context.WithCancel(d.lifetime())
	v.cancel = cancel
	v.done = make(chan struct{})
	v.nudge = make(chan struct{}, 1)
	// The loop is handed its own channels rather than reading the fields:
	// stopLoopLocked clears them and a later startLoopLocked replaces
	// them, both under d.mu, and the goroutine may not have run yet when
	// that happens — an Unmount landing right behind a Mount would
	// otherwise find v.done already nil and close(nil).
	go d.runVolume(ctx, v, v.nudge, v.done, initial, seed)
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
//
// A volume carrying the client certificate also has a timer, re-armed after
// every refresh from what that refresh produced (nextCertRefresh). It fires
// regardless of eventsDriving: a certificate ages without Vault saying
// anything, so no event will ever arrive to replace it.
func (d *Driver) runVolume(ctx context.Context, v *volume, nudge <-chan struct{}, done chan struct{}, initial bool, seed *clientcert.Pair) {
	defer close(done)
	certTimer := time.NewTimer(time.Hour)
	certTimer.Stop()
	defer certTimer.Stop()
	var certC <-chan time.Time // nil, so never selected, while unarmed
	var sched certSchedule
	rearm := func(pair *clientcert.Pair, err error) {
		delay, ok := d.nextCertRefresh(v.Spec, pair, err, &sched)
		if !ok {
			return
		}
		certTimer.Reset(delay)
		certC = certTimer.C
	}
	if initial {
		rearm(d.refresh(ctx, v))
	} else {
		rearm(seed, nil)
	}
	ticker := time.NewTicker(v.Spec.TTL)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-nudge:
			select {
			case <-time.After(eventDebounce):
			case <-ctx.Done():
				return
			}
			// Drain anything that arrived during the debounce; it is
			// covered by the render about to happen.
			select {
			case <-nudge:
			default:
			}
			rearm(d.refresh(ctx, v))
		case <-ticker.C:
			if d.eventsDriving() {
				continue
			}
			rearm(d.refresh(ctx, v))
		case <-certC:
			slog.Debug("docker volume client certificate due; re-rendering", "volume", v.Name)
			rearm(d.refresh(ctx, v))
		}
	}
}

// refresh re-renders v under its opMu and records the outcome, returning the
// certificate pair the render wrote (nil when the volume carries none) and
// the error, so the loop can schedule the certificate's next refresh.
func (d *Driver) refresh(ctx context.Context, v *volume) (*clientcert.Pair, error) {
	if v.Spec.ClientCert != ClientCertOnly && !d.hasToken() {
		// A resumed volume can be running before the daemon has
		// authenticated. Asking Vault without a token would only turn one
		// known condition into a per-tick 400; record it and try again on
		// the next tick or nudge. A client_cert=only volume reads no
		// secrets, so it is not held back here: a held certificate needs
		// no token at all, and a source that does need one reports
		// clientcert.ErrNoToken itself.
		d.recordRefresh(v, 0, ErrNoToken)
		return nil, ErrNoToken
	}
	ctx, cancel := context.WithTimeout(ctx, refreshTimeout)
	defer cancel()
	v.opMu.Lock()
	n, pair, err := materialise(ctx, d.store, d.opts.ClientCert, d.volumePath(v.Name), v.Spec)
	v.opMu.Unlock()
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		// Shutdown or unmount mid-render: not a failure worth recording
		// against a volume that is about to be wiped or resumed.
		return nil, err
	}
	d.recordRefresh(v, n, err)
	return pair, err
}

// Certificate schedule. A volume carrying the client certificate is
// re-rendered when the certificate falls due, because nothing else would:
// Vault sends no event when a certificate ages, and on Enterprise the ticker
// is suppressed while a subscription is live.
const (
	// defaultCertRetry is the re-arm after the source answers that it
	// cannot serve a certificate yet (sign pacing, no token). Both clear in
	// seconds and the files are about to expire, so waiting out the ttl
	// would be wrong. It is also the first step of the overdue backoff (see
	// nextCertRefresh). Driver.certRetry carries it so a test can shorten
	// it for one driver without racing another test's loops.
	defaultCertRetry = 10 * time.Second
	// certTimerMin is the shortest the certificate timer is armed for.
	certTimerMin = time.Second
	// certJitterDivisor bounds the jitter to 1/20 (5%) of the certificate's
	// issued lifetime, so volumes signed together do not all re-render (and
	// re-sign) in the same instant.
	certJitterDivisor = 20
	// certWindowDivisor additionally bounds the jitter to 1/10 of the
	// window between RefreshAt and NotAfter. For a short-lived certificate
	// RefreshAt is the half-life, so the two bounds agree; the second one
	// only guards a source whose RefreshAt sits late in the lifetime.
	certWindowDivisor = 10
)

// certJitterBound is the most nextCertRefresh may add past RefreshAt.
//
// A held pair gets none. Jitter exists to spread re-signs, and nothing is
// signed for a held certificate: the daemon rotates it (and, with
// revoke_superseded, revokes the copy this volume holds) within about an
// hour of RefreshAt, so any delay past RefreshAt is only time spent serving
// a certificate that is about to stop working. The overdue backoff then
// re-checks at most every volume ttl until the rotation lands.
func certJitterBound(pair *clientcert.Pair) time.Duration {
	if pair.Source == clientcert.SourceHeld {
		return 0
	}
	lifetime := pair.NotAfter.Sub(pair.NotBefore)
	window := pair.NotAfter.Sub(pair.RefreshAt)
	if lifetime <= 0 || window <= 0 {
		return 0
	}
	return min(lifetime/certJitterDivisor, window/certWindowDivisor)
}

// certSchedule is the per-loop state nextCertRefresh carries between arms.
type certSchedule struct {
	// overdue counts consecutive successful refreshes whose pair was
	// already past its RefreshAt.
	overdue int
}

// nextCertRefresh decides when the certificate timer next fires after a
// refresh that produced pair and err, and whether it is armed at all. It is
// never armed for a volume that does not carry the certificate.
//
//   - Success: the pair's RefreshAt, plus — for a short-lived pair only —
//     jitter of at most 5% of the issued lifetime and at most a tenth of
//     the RefreshAt-to-NotAfter window (see certJitterBound), and never
//     less than certTimerMin. A held pair fires at RefreshAt exactly.
//   - Success with a pair already past its RefreshAt: the source has
//     nothing newer to give yet — a held certificate the daemon has not
//     rotated, or an ephemeral one whose re-sign is paced and which is
//     still valid. Re-rendering at the 1s floor would re-read every
//     selected secret from Vault each second, so this backs off from
//     d.certRetry, doubling to the ticker's cadence, but never past
//     NotAfter (plus certTimerMin), so an expired pair is always replaced
//     as soon as the source can sign again.
//   - Failure the source expects to clear shortly (ErrSignPaced, no token
//     whether the source or the driver noticed, a token replacement still
//     in progress, or this render's deadline running out while a sign was
//     in flight): d.certRetry.
//   - Any other failure, or no pair reported: the ordinary ticker cadence.
func (d *Driver) nextCertRefresh(spec Spec, pair *clientcert.Pair, err error, s *certSchedule) (time.Duration, bool) {
	if spec.ClientCert == ClientCertOff {
		return 0, false
	}
	switch {
	case err != nil && (errors.Is(err, clientcert.ErrSignPaced) || errors.Is(err, clientcert.ErrNoToken) || errors.Is(err, ErrNoToken) ||
		errors.Is(err, clientcert.ErrReauthInProgress) || errors.Is(err, clientcert.ErrSignInProgress)):
		return d.certRetry, true
	case err != nil, pair == nil:
		return spec.TTL, true
	}
	until := pair.RefreshAt.Sub(d.now())
	if until <= 0 {
		ceiling := max(spec.TTL, d.certRetry)
		delay := d.certRetry
		for range s.overdue {
			if delay >= ceiling {
				break
			}
			delay *= 2
		}
		if delay < ceiling {
			s.overdue++
		}
		delay = min(delay, ceiling)
		// Never back off past the certificate's expiry. A source that
		// cannot sign right now (a transient Vault failure) still answers
		// with its cached pair while that pair is valid, so a backoff
		// step that overran NotAfter would leave the container holding
		// an expired client.crt long after Vault recovered. Firing just
		// after NotAfter guarantees the source must try again.
		if exp := pair.NotAfter.Sub(d.now()); exp > 0 {
			delay = min(delay, exp+certTimerMin)
		}
		return delay, true
	}
	s.overdue = 0
	until += d.jitter(certJitterBound(pair))
	return max(until, certTimerMin), true
}

// defaultJitter returns a uniformly random duration in [0, bound].
func defaultJitter(bound time.Duration) time.Duration {
	if bound <= 0 {
		return 0
	}
	return rand.N(bound + 1)
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
		if !v.Spec.Covers(rel) {
			continue
		}
		slog.Debug("vault event concerns docker volume", "volume", v.Name, "path", displayPath(rel), "type", evt.EventType)
		switch {
		case v.cancel != nil:
			nudge(v)
		case v.populating > 0:
			v.pendingEvent = true
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
				// The subscriber closes both channels after sending its
				// error; the closed event channel can win the select, so
				// look for the error before calling the close clean.
				select {
				case err, ok := <-errCh:
					if ok && err != nil {
						return err
					}
				default:
				}
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
// other entry — an unmounted volume's leftovers, or a name no longer known
// — is removed so no secret outlives the container that needed it.
//
// Only entries that could be volume directories are touched: a name that
// fails ValidateName was never created by this driver, so it is left alone
// and named in a warning. The stronger guard against removing something
// that is not ours is prepareVolumeRoot's marker check, which refuses to
// adopt a non-empty directory the driver did not create.
func (d *Driver) resume() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, v := range d.volumes {
		if len(v.Mounts) > 0 {
			slog.Info("resuming docker volume still mounted by the engine", "volume", v.Name, "mounts", len(v.Mounts))
			d.startLoopLocked(v, true, nil)
		}
	}
	entries, err := os.ReadDir(d.opts.VolumeDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == volumeDirMarker {
			continue
		}
		if v, ok := d.volumes[name]; ok && v.cancel != nil {
			continue
		}
		p := d.volumePath(name)
		if ValidateName(name) != nil || !e.IsDir() {
			slog.Warn("unexpected entry in the docker volume directory; leaving it alone", "path", p)
			continue
		}
		if err := os.RemoveAll(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			slog.Warn("could not remove stale docker volume directory", "path", p, "error", err)
		}
	}
}

// volumeDirMarker is an empty file the driver leaves in VolumeDir to record
// that the directory is its own. resume removes entries from that directory
// wholesale, and a mistyped docker.volume_dir naming an existing directory
// full of the user's files must not become a startup that deletes them.
const volumeDirMarker = ".dotvault-volumes"

// prepareVolumeRoot creates VolumeDir at 0700, or adopts an existing one
// only if it carries the marker or is empty — anything else is refused.
func (d *Driver) prepareVolumeRoot() error {
	dir := d.opts.VolumeDir
	marker := filepath.Join(dir, volumeDirMarker)
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create volume dir: %w", err)
		}
	case err != nil:
		return fmt.Errorf("stat volume dir: %w", err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("volume dir %s is a symlink; point docker.volume_dir at a real directory", dir)
	case !info.IsDir():
		return fmt.Errorf("volume dir %s exists and is not a directory", dir)
	default:
		if _, err := os.Lstat(marker); err != nil {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return fmt.Errorf("read volume dir: %w", err)
			}
			if len(entries) > 0 {
				return fmt.Errorf("volume dir %s is not empty and was not created by dotvault; refusing to manage it (point docker.volume_dir at an empty or new directory)", dir)
			}
		}
	}
	// Tighten a pre-existing directory: everything beneath it is secret.
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("chmod volume dir: %w", err)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		return fmt.Errorf("write volume dir marker: %w", err)
	}
	return nil
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
