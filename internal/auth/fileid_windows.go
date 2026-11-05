//go:build windows

package auth

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileIdentity is the volume serial number and file index. os.Stat does not
// report them, so it opens the file for attributes only, sharing read, write
// and delete so a concurrent writer's rename is never blocked. A failure
// leaves the identity zero: the version then rests on mtime and size alone.
func fileIdentity(path string, _ os.FileInfo) fileID {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileID{}
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fileID{}
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fileID{}
	}
	return fileID{
		vol: uint64(info.VolumeSerialNumber),
		idx: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}
}
