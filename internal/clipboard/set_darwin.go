package clipboard

// pbcopy ships with macOS and writes the general pasteboard from stdin.
func platformSet(text string) error {
	return execSet([]tool{{name: "pbcopy"}}, text)
}
