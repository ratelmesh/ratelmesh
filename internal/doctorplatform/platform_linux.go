//go:build linux

package doctorplatform

func currentPlatformOps() platformOps { return linuxPlatformOps() }
