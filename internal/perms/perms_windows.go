//go:build windows

package perms

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Broad SID types that indicate overly permissive access.
var broadSIDTypes = []windows.WELL_KNOWN_SID_TYPE{
	windows.WinWorldSid,              // S-1-1-0 (Everyone)
	windows.WinBuiltinUsersSid,       // S-1-5-32-545 (Users)
	windows.WinAuthenticatedUserSid,  // S-1-5-11 (Authenticated Users)
}

// anyAccessMask covers any meaningful access right.
const anyAccessMask windows.ACCESS_MASK = windows.STANDARD_RIGHTS_ALL |
	windows.FILE_GENERIC_READ |
	windows.FILE_GENERIC_WRITE |
	windows.FILE_GENERIC_EXECUTE |
	windows.GENERIC_ALL |
	windows.GENERIC_READ |
	windows.GENERIC_WRITE |
	windows.GENERIC_EXECUTE

// writeAccessMask covers write-related access rights.
const writeAccessMask windows.ACCESS_MASK = windows.FILE_WRITE_DATA |
	windows.FILE_WRITE_ATTRIBUTES |
	windows.FILE_WRITE_EA |
	windows.FILE_APPEND_DATA |
	windows.GENERIC_WRITE |
	windows.GENERIC_ALL

// IsPrivateFile reports whether path is accessible only by its owner.
// On Windows this checks that the DACL does not grant any access to
// Everyone, Users, or Authenticated Users.
func IsPrivateFile(path string) (bool, error) {
	return checkBroadSIDsHaveAccess(path, anyAccessMask)
}

// IsGroupWorldWritable reports whether path is writable by broad groups.
// On Windows this checks that the DACL does not grant write access to
// Everyone, Users, or Authenticated Users.
func IsGroupWorldWritable(path string) (bool, error) {
	return checkBroadSIDsHaveAccess(path, writeAccessMask)
}

// checkBroadSIDsHaveAccess returns true if any DACL entry grants the
// specified access rights to a well-known broad SID.
func checkBroadSIDsHaveAccess(path string, mask windows.ACCESS_MASK) (bool, error) {
	// Verify the file exists first to return a consistent os-level error.
	if _, err := os.Stat(path); err != nil {
		return false, err
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	// A nil DACL means no access control — treat as insecure.
	if dacl == nil {
		return true, nil
	}

	broadSIDs := make([]*windows.SID, 0, len(broadSIDTypes))
	for _, st := range broadSIDTypes {
		sid, err := windows.CreateWellKnownSid(st)
		if err != nil {
			continue
		}
		broadSIDs = append(broadSIDs, sid)
	}

	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			continue
		}

		// Only inspect allow entries — deny entries restrict access.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}

		if ace.Mask&mask == 0 {
			continue
		}

		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, broad := range broadSIDs {
			if aceSID.Equals(broad) {
				return true, nil
			}
		}
	}

	return false, nil
}
