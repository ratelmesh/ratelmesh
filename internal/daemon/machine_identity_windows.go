//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func platformMachineID() (string, error) {
	reg := filepath.Join(os.Getenv("SystemRoot"), "System32", "reg.exe")
	out, err := exec.Command(reg, "QUERY", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return "", nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.EqualFold(fields[0], "MachineGuid") {
			return fields[len(fields)-1], nil
		}
	}
	return "", nil
}
