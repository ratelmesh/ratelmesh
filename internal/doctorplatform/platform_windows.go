//go:build windows

package doctorplatform

func currentPlatformOps() platformOps { return windowsPlatformOps() }
