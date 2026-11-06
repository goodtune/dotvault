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
func secretChangeHook(triggerSync func(), hub *events.Hub) func(source string) enrol.ChangeFunc {
	return func(source string) enrol.ChangeFunc {
		return func(c enrol.Change) {
			triggerSync()
			// Version 0 means Vault's response carried no version. A notice
			// without one cannot be deduplicated, so it is not sent; the
			// peers' own refresh checks still pick the change up.
			if c.Local && c.Version > 0 {
				hub.Publish(events.Event{Key: c.Key, Version: c.Version, Source: source})
			}
		}
	}
}
