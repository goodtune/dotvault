//go:build !unix && !windows

package auth

import "os"

// fileIdentity has nothing to report here; the version rests on mtime and
// size alone.
func fileIdentity(string, os.FileInfo) fileID { return fileID{} }
