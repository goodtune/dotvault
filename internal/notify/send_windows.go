//go:build windows

package notify

import "git.sr.ht/~jackmordaunt/go-toast"

// platformDeliver is the Windows delivery path. When msg carries no ActionURL
// it uses the shared beeep path (unchanged). When it does, it builds a
// protocol-activated toast via go-toast directly — beeep exposes no activation
// API — so clicking the toast opens the URL. This is fire-and-forget: Windows'
// shell handles the click, so no lingering handler is needed even though the
// notification was raised inside a one-shot delivery call (the peer's request
// handler). It cannot be exercised in the (Linux) CI, like the TPM backend.
func platformDeliver(msg Message) error {
	urgent := levelTable[msg.Level].urgent
	if msg.ActionURL == "" {
		return beeepDeliver(urgent, msg.Title, msg.Body, iconArg(msg.Level))
	}
	return clickableToast(msg, urgent)
}

// clickableToast raises a go-toast notification whose whole-toast activation
// opens the (encoded) action URL. Title/Body are already sanitized by
// NewMessage (the CDATA/PowerShell neutralization); the URL is encoded for the
// launch attribute's XML/here-string sinks by safeToastArgs.
func clickableToast(msg Message, urgent bool) error {
	audio := toast.Silent
	if urgent {
		audio = toast.Default
	}
	n := toast.Notification{
		AppID:               appName,
		Title:               msg.Title,
		Body:                msg.Body,
		ActivationType:      toast.Protocol,
		ActivationArguments: safeToastArgs(msg.ActionURL),
		Audio:               audio,
	}
	return n.Push()
}
