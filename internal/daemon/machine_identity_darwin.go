//go:build darwin && !ios

package daemon

import (
	"fmt"
	"os/exec"
	"strings"
)

func platformMachineID() (string, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("read IOPlatformUUID: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, `"IOPlatformUUID"`) {
			continue
		}
		parts := strings.Split(line, `"`)
		if len(parts) >= 4 {
			return strings.TrimSpace(parts[len(parts)-2]), nil
		}
	}
	return "", fmt.Errorf("read IOPlatformUUID: value not found")
}
