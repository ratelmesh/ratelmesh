//go:build darwin

package doctorplatform

func currentPlatformOps() platformOps { return darwinPlatformOps() }
