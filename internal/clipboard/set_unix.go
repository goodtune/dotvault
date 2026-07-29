//go:build linux || freebsd || netbsd || openbsd

package clipboard

// Candidate order: wl-copy first — on a Wayland session it is the native
// writer, and on X11 it fails fast (no Wayland socket) and falls through —
// then the X11 tools. All write the CLIPBOARD selection (the paste-with-Ctrl-V
// one), not PRIMARY. The GOOS set matches beeep's unix notification backend:
// the same desktop sessions that can show the remote-notify notification can
// take a clipboard write.
func platformSet(text string) error {
	return execSet([]tool{
		{name: "wl-copy"},
		{name: "xclip", args: []string{"-selection", "clipboard"}},
		{name: "xsel", args: []string{"--clipboard", "--input"}},
	}, text)
}
