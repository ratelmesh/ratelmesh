//go:build (!darwin && !linux && !windows) || ios

package daemon

func platformMachineID() (string, error) { return "", nil }
