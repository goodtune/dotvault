//go:build !windows && !darwin && !linux

package enrol

func tryClipboard(_ string) {}
