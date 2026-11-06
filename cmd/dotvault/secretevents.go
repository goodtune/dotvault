package main

import (
	"github.com/goodtune/dotvault/internal/enrol"
	"github.com/goodtune/dotvault/internal/events"
)

// secretChangeHook builds the enrolment managers' change hooks. Every change
// triggers a sync; only a change this process wrote is published, because a
// change it merely observed was written — and announced — by another daemon.
// Publishing an observed change as well would turn every peer into an echo of
// every other.
//
// A published write is first recorded in seen, the table the peer relay also
// consults, so the same notice coming back from a peer is not re-announced.
func secretChangeHook(triggerSync func(), hub *events.Hub, seen *events.Seen) func(source string) enrol.ChangeFunc {
	return func(source string) enrol.ChangeFunc {
		return func(c enrol.Change) {
			triggerSync()
			if !c.Local {
				return
			}
			// Version 0 means Vault's response carried no version. A notice
			// without one cannot be deduplicated, so it is not sent; the
			// peers' own refresh checks still pick the change up. Seen
			// refuses it for the same reason.
			e := events.Event{Key: c.Key, Version: c.Version, Source: source}
			if seen.Admit(e) {
				hub.Publish(e)
			}
		}
	}
}

// relayedNotice is the peer relay's callback in the daemon: sync this host's
// files, and re-announce the notice so whatever borrows from this host —
// another daemon chained further downstream, or a client-facade subscriber —
// hears it too. The relay has already deduplicated it.
func relayedNotice(triggerSync func(), hub *events.Hub) func(events.Event) {
	return func(e events.Event) {
		triggerSync()
		hub.Publish(e)
	}
}
