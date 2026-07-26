package remoteservice

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	windowsSSHInspectScript = `$ErrorActionPreference='Stop';` +
		`$s=Get-CimInstance Win32_Service -Filter "Name='sshd'";if($null -eq $s){exit 3};` +
		`$run=[int]$s.Started;$servicePID=[uint64]$s.ProcessId;$gen=[uint64]0;$listen=[int]0;` +
		`if($servicePID -ne 0){$gen=[uint64]([System.Diagnostics.Process]::GetProcessById([int]$servicePID).StartTime.ToUniversalTime().Ticks);` +
		`$listen=[int](@(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -eq $servicePID}).Count -gt 0)};` +
		`[Console]::WriteLine("ServiceEnabled=$([int]($s.StartMode -ne 'Disabled'))");[Console]::WriteLine("Running=$run");` +
		`[Console]::WriteLine("PID=$servicePID");[Console]::WriteLine("Generation=$gen");[Console]::WriteLine("Listening=$listen")`
	// RDP is exposed only on the fixed RatelMesh interface and CGNAT mesh range.
	// Future IPv6 support must add an explicit RatelMesh ULA prefix here and in
	// the corresponding strict inspector; it must not broaden this rule to Any.
	windowsRDPInspectScript = `$ErrorActionPreference='Stop';` +
		`$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server');` +
		`if($null -eq $k){exit 3};` +
		`$p=[int]$k.GetValue('fDenyTSConnections',1);$k.Close();` +
		`$tcp=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'RemoteDesktop-UserMode-In-TCP');` +
		`$udp=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name 'RemoteDesktop-UserMode-In-UDP');` +
		`$unique=[int]($tcp.Count -eq 1 -and $udp.Count -eq 1);` +
		`function Test-RDPFirewallRule($r,[string]$protocol){if($r.Count -ne 1){return $false};` +
		`$q=$r[0];if($q.Enabled.ToString() -ne 'True' -or $q.Action.ToString() -ne 'Allow' -or $q.Direction.ToString() -ne 'Inbound' -or $q.Profile.ToString() -ne 'Any'){return $false};` +
		`$pf=@($q|Get-NetFirewallPortFilter);$af=@($q|Get-NetFirewallAddressFilter);$ap=@($q|Get-NetFirewallApplicationFilter);` +
		`$sf=@($q|Get-NetFirewallServiceFilter);$it=@($q|Get-NetFirewallInterfaceTypeFilter);$ia=@($q|Get-NetFirewallInterfaceFilter);` +
		`return $pf.Count -eq 1 -and $pf[0].Protocol.ToString() -eq $protocol -and (@($pf[0].LocalPort)-join ',') -eq '3389' -and (@($pf[0].RemotePort)-join ',') -eq 'Any' ` +
		`-and $af.Count -eq 1 -and (@($af[0].LocalAddress)-join ',') -eq 'Any' -and (@($af[0].RemoteAddress)-join ',') -eq '100.64.0.0/10' ` +
		`-and $ap.Count -eq 1 -and $ap[0].Program.ToString() -eq '%SystemRoot%\System32\svchost.exe' -and $sf.Count -eq 1 -and $sf[0].Service.ToString() -eq 'TermService' ` +
		`-and $it.Count -eq 1 -and $it[0].InterfaceType.ToString() -eq 'Any' -and $ia.Count -eq 1 -and (@($ia[0].InterfaceAlias)-join ',') -eq 'ratelmesh0'};` +
		`$f=[int]((Test-RDPFirewallRule $tcp 'TCP') -and (Test-RDPFirewallRule $udp 'UDP'));` +
		`$snapshotParts=@();foreach($q in @($tcp+$udp)|Sort-Object Name){$pf=@($q|Get-NetFirewallPortFilter);$af=@($q|Get-NetFirewallAddressFilter);` +
		`$ap=@($q|Get-NetFirewallApplicationFilter);$sf=@($q|Get-NetFirewallServiceFilter);$it=@($q|Get-NetFirewallInterfaceTypeFilter);$ia=@($q|Get-NetFirewallInterfaceFilter);` +
		`$snapshotParts+=@($q.Name,$q.Enabled,$q.Action,$q.Direction,$q.Profile,$pf.Protocol,(@($pf.LocalPort)-join ','),(@($pf.RemotePort)-join ','),(@($af.LocalAddress)-join ','),(@($af.RemoteAddress)-join ','),$ap.Program,$sf.Service,$it.InterfaceType,(@($ia.InterfaceAlias)-join ','))-join '|'};` +
		`$sha=[System.Security.Cryptography.SHA256]::Create();$snapshot=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($snapshotParts-join ';'))))).Replace('-','').ToLowerInvariant();` +
		`$s=Get-CimInstance Win32_Service -Filter "Name='TermService'";if($null -eq $s){exit 3};` +
		`$run=[int]$s.Started;$servicePID=[uint64]$s.ProcessId;$gen=[uint64]0;$listen=[int]0;` +
		`if($servicePID -ne 0){$gen=[uint64]([System.Diagnostics.Process]::GetProcessById([int]$servicePID).StartTime.ToUniversalTime().Ticks);` +
		`$listen=[int](@(Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -eq $servicePID}).Count -gt 0)};` +
		`[Console]::WriteLine("PolicyEnabled=$([int]($p -eq 0))");[Console]::WriteLine("FirewallRulesUnique=$unique");` +
		`[Console]::WriteLine("FirewallEnabled=$f");[Console]::WriteLine("FirewallSnapshot=$snapshot");` +
		`[Console]::WriteLine("ServiceEnabled=$([int]($s.StartMode -ne 'Disabled'))");[Console]::WriteLine("Running=$run");` +
		`[Console]::WriteLine("PID=$servicePID");[Console]::WriteLine("Generation=$gen");[Console]::WriteLine("Listening=$listen")`
	windowsRDPEnablePolicyScript = `$ErrorActionPreference='Stop';` +
		`$k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Terminal Server',$true);` +
		`if($null -eq $k){exit 3};$k.SetValue('fDenyTSConnections',0,[Microsoft.Win32.RegistryValueKind]::DWord);$k.Close()`
	windowsRDPRulePreflightScript = `$tcp=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'RemoteDesktop-UserMode-In-TCP');` +
		`$udp=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name 'RemoteDesktop-UserMode-In-UDP');` +
		`if($tcp.Count -ne 1 -or $udp.Count -ne 1){exit 3};`
	windowsRDPFirewallShapeScript = windowsRDPRulePreflightScript +
		`function Test-RDPFirewallRule($r,[string]$protocol,[string]$enabled){$q=$r[0];` +
		`if($q.Enabled.ToString() -ne $enabled -or $q.Action.ToString() -ne 'Allow' -or $q.Direction.ToString() -ne 'Inbound' -or $q.Profile.ToString() -ne 'Any'){return $false};` +
		`$pf=@($q|Get-NetFirewallPortFilter);$af=@($q|Get-NetFirewallAddressFilter);$ap=@($q|Get-NetFirewallApplicationFilter);` +
		`$sf=@($q|Get-NetFirewallServiceFilter);$it=@($q|Get-NetFirewallInterfaceTypeFilter);$ia=@($q|Get-NetFirewallInterfaceFilter);` +
		`return $pf.Count -eq 1 -and $pf[0].Protocol.ToString() -eq $protocol -and (@($pf[0].LocalPort)-join ',') -eq '3389' -and (@($pf[0].RemotePort)-join ',') -eq 'Any' ` +
		`-and $af.Count -eq 1 -and (@($af[0].LocalAddress)-join ',') -eq 'Any' -and (@($af[0].RemoteAddress)-join ',') -eq '100.64.0.0/10' ` +
		`-and $ap.Count -eq 1 -and $ap[0].Program.ToString() -eq '%SystemRoot%\System32\svchost.exe' -and $sf.Count -eq 1 -and $sf[0].Service.ToString() -eq 'TermService' ` +
		`-and $it.Count -eq 1 -and $it[0].InterfaceType.ToString() -eq 'Any' -and $ia.Count -eq 1 -and (@($ia[0].InterfaceAlias)-join ',') -eq 'ratelmesh0'};`
	windowsRDPDisableFirewallScript = `$ErrorActionPreference='Stop';` + windowsRDPRulePreflightScript +
		`@($tcp+$udp)|Set-NetFirewallRule -Enabled False`
	windowsRDPEnableFirewallScript = `$ErrorActionPreference='Stop';` + windowsRDPRulePreflightScript +
		`$tcp|Set-NetFirewallRule -Enabled False -Action Allow -Direction Inbound -Profile Any;` +
		`$udp|Set-NetFirewallRule -Enabled False -Action Allow -Direction Inbound -Profile Any`
	windowsRDPEnablePortScript = `$ErrorActionPreference='Stop';` + windowsRDPRulePreflightScript +
		`$tcp|Get-NetFirewallPortFilter|Set-NetFirewallPortFilter -Protocol TCP -LocalPort 3389 -RemotePort Any;` +
		`$udp|Get-NetFirewallPortFilter|Set-NetFirewallPortFilter -Protocol UDP -LocalPort 3389 -RemotePort Any`
	windowsRDPEnableAddressScript = `$ErrorActionPreference='Stop';` + windowsRDPRulePreflightScript +
		`@($tcp+$udp)|Get-NetFirewallAddressFilter|Set-NetFirewallAddressFilter -LocalAddress Any -RemoteAddress '100.64.0.0/10'`
	windowsRDPEnableBindingScript = `$ErrorActionPreference='Stop';` + windowsRDPRulePreflightScript +
		`@($tcp+$udp)|Get-NetFirewallApplicationFilter|Set-NetFirewallApplicationFilter -Program '%SystemRoot%\System32\svchost.exe';` +
		`@($tcp+$udp)|Get-NetFirewallServiceFilter|Set-NetFirewallServiceFilter -Service TermService;` +
		`@($tcp+$udp)|Get-NetFirewallInterfaceTypeFilter|Set-NetFirewallInterfaceTypeFilter -InterfaceType Any;` +
		`@($tcp+$udp)|Get-NetFirewallInterfaceFilter|Set-NetFirewallInterfaceFilter -InterfaceAlias ratelmesh0`
	windowsRDPVerifyDisabledScript = `$ErrorActionPreference='Stop';` + windowsRDPFirewallShapeScript +
		`if(-not ((Test-RDPFirewallRule $tcp 'TCP' 'False') -and (Test-RDPFirewallRule $udp 'UDP' 'False'))){exit 3}`
	windowsRDPFinalEnableScript = `$ErrorActionPreference='Stop';` + windowsRDPFirewallShapeScript +
		`if(-not ((Test-RDPFirewallRule $tcp 'TCP' 'False') -and (Test-RDPFirewallRule $udp 'UDP' 'False'))){exit 3};` +
		`try{@($tcp+$udp)|Set-NetFirewallRule -Enabled True}catch{@($tcp+$udp)|Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue;throw}`
	windowsRDPVerifyEnabledScript = `$ErrorActionPreference='Stop';` + windowsRDPFirewallShapeScript +
		`if(-not ((Test-RDPFirewallRule $tcp 'TCP' 'True') -and (Test-RDPFirewallRule $udp 'UDP' 'True'))){exit 3}`
)

func (b *SystemBackend) enableFixed(ctx context.Context, service fixedService) error {
	switch service {
	case fixedLinuxSSH, fixedLinuxSSHD:
		_, err := b.run(ctx, commandSpec{
			executable: "/usr/bin/systemctl",
			arguments:  []string{"enable", linuxUnitName(service)},
		})
		return err
	case fixedMacSSH:
		_, err := b.run(ctx, commandSpec{
			executable: "/usr/sbin/systemsetup",
			arguments:  []string{"-setremotelogin", "on"},
		})
		return err
	case fixedWindowsSSH:
		_, err := b.run(ctx, commandSpec{
			executable: `C:\Windows\System32\sc.exe`,
			arguments:  []string{"config", windowsServiceName(service), "start=", "demand"},
		})
		return err
	case fixedWindowsRDP:
		// Keep both rules disabled until every mesh-only filter has been
		// configured and independently verified. Policy and service changes
		// happen only after the final enabled-state verification.
		for _, script := range []string{
			windowsRDPDisableFirewallScript,
			windowsRDPEnableFirewallScript,
			windowsRDPEnablePortScript,
			windowsRDPEnableAddressScript,
			windowsRDPEnableBindingScript,
			windowsRDPVerifyDisabledScript,
			windowsRDPFinalEnableScript,
			windowsRDPVerifyEnabledScript,
			windowsRDPEnablePolicyScript,
		} {
			if _, err := b.run(ctx, powershellSpec(script)); err != nil {
				return err
			}
		}
		_, err := b.run(ctx, commandSpec{
			executable: `C:\Windows\System32\sc.exe`,
			arguments:  []string{"config", "TermService", "start=", "demand"},
		})
		return err
	default:
		return &Error{Code: CodeUnsupportedTarget}
	}
}

func (b *SystemBackend) startFixed(ctx context.Context, service fixedService) error {
	switch service {
	case fixedLinuxSSH, fixedLinuxSSHD:
		_, err := b.run(ctx, commandSpec{
			executable: "/usr/bin/systemctl",
			arguments:  []string{"start", linuxUnitName(service)},
		})
		return err
	case fixedMacSSH:
		_, err := b.run(ctx, commandSpec{
			executable: "/usr/sbin/systemsetup",
			arguments:  []string{"-setremotelogin", "on"},
		})
		return err
	case fixedWindowsSSH, fixedWindowsRDP:
		_, err := b.run(ctx, commandSpec{
			executable: `C:\Windows\System32\sc.exe`,
			arguments:  []string{"start", windowsServiceName(service)},
		})
		return err
	default:
		return &Error{Code: CodeUnsupportedTarget}
	}
}

func (b *SystemBackend) linuxListening(ctx context.Context, pid uint64, port uint16) (bool, error) {
	result, err := b.run(ctx, commandSpec{
		executable: "/usr/bin/ss",
		arguments:  []string{"-H", "-ltnp"},
	})
	if err != nil {
		return false, err
	}
	return linuxOutputHasPortPID(result.stdout, port, pid), nil
}

func (b *SystemBackend) macTrustedSSHListener(ctx context.Context) (bool, uint64, error) {
	result, err := b.run(ctx, commandSpec{
		executable: "/usr/sbin/lsof",
		arguments:  []string{"-nP", "-iTCP:22", "-sTCP:LISTEN"},
	})
	if err != nil {
		return false, 0, err
	}
	return macOutputHasTrustedSSHListener(result.stdout)
}

func powershellSpec(script string) commandSpec {
	return commandSpec{
		executable: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		arguments:  []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script},
	}
}

func linuxOutputHasPortPID(output string, port uint16, pid uint64) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[0] != "LISTEN" ||
			!endpointHasPort(fields[3], port) {
			continue
		}
		if processFieldHasPID(strings.Join(fields[5:], " "), pid) {
			return true
		}
	}
	return false
}

func macOutputHasPortPID(output string, port uint16, pid uint64) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[len(fields)-1] != "(LISTEN)" {
			continue
		}
		parsedPID, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || parsedPID != pid {
			continue
		}
		for _, field := range fields[2:] {
			if endpointHasPort(field, port) {
				return true
			}
		}
	}
	return false
}

func macOutputHasTrustedSSHListener(output string) (bool, uint64, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[len(fields)-1] != "(LISTEN)" {
			continue
		}
		if fields[0] != "launchd" && fields[0] != "sshd" {
			continue
		}
		pid, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || pid == 0 {
			return false, 0, errBackendState
		}
		for _, field := range fields[2:] {
			if endpointHasPort(field, 22) {
				return true, pid, nil
			}
		}
	}
	return false, 0, nil
}

func endpointHasPort(endpoint string, expected uint16) bool {
	endpoint = strings.TrimSpace(endpoint)
	_, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		index := strings.LastIndexByte(endpoint, ':')
		if index < 0 || index == len(endpoint)-1 {
			return false
		}
		portText = endpoint[index+1:]
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && uint16(portValue) == expected
}

func processFieldHasPID(field string, expected uint64) bool {
	for {
		index := strings.Index(field, "pid=")
		if index < 0 {
			return false
		}
		field = field[index+len("pid="):]
		end := 0
		for end < len(field) && field[end] >= '0' && field[end] <= '9' {
			end++
		}
		if end > 0 {
			pid, err := strconv.ParseUint(field[:end], 10, 64)
			if err == nil && pid == expected {
				return true
			}
		}
		if end == 0 {
			field = field[1:]
			continue
		}
		if end >= len(field) {
			return false
		}
		field = field[end:]
	}
}

func (b *SystemBackend) run(ctx context.Context, spec commandSpec) (commandResult, error) {
	if ctx == nil {
		return commandResult{}, &Error{Code: CodeInvalidRequest}
	}
	if !allowedCommand(spec) {
		return commandResult{}, errBackendUnsupported
	}
	runCtx, cancel := context.WithTimeout(ctx, systemCommandTimeout)
	defer cancel()
	result, err := b.runner.Run(runCtx, cloneCommand(spec), systemOutputLimit)
	if contextErr := runCtx.Err(); contextErr != nil {
		return commandResult{}, contextErr
	}
	if result.truncated || len(result.stdout) > systemOutputLimit || len(result.stderr) > systemOutputLimit {
		return commandResult{}, errors.New("remote service command output limit")
	}
	if err != nil {
		return commandResult{}, &commandExecutionError{cause: err}
	}
	return result, nil
}

func cloneCommand(spec commandSpec) commandSpec {
	return commandSpec{
		executable: spec.executable,
		arguments:  append([]string(nil), spec.arguments...),
	}
}

func allowedCommand(spec commandSpec) bool {
	switch spec.executable {
	case "/usr/bin/systemctl":
		return allowedSystemctl(spec.arguments)
	case "/usr/bin/ss":
		return equalArguments(spec.arguments, "-H", "-ltnp")
	case "/usr/sbin/lsof":
		return allowedLsof(spec.arguments)
	case "/usr/sbin/systemsetup":
		return equalArguments(spec.arguments, "-getremotelogin") ||
			equalArguments(spec.arguments, "-setremotelogin", "on")
	case `C:\Windows\System32\sc.exe`:
		return allowedSC(spec.arguments)
	case `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`:
		return allowedPowerShell(spec.arguments)
	default:
		return false
	}
}

func allowedPowerShell(arguments []string) bool {
	if len(arguments) != 5 ||
		!equalArguments(arguments[:4], "-NoLogo", "-NoProfile", "-NonInteractive", "-Command") {
		return false
	}
	script := arguments[4]
	if script == windowsSSHInspectScript ||
		script == windowsRDPInspectScript ||
		script == windowsRDPEnablePolicyScript ||
		script == windowsRDPDisableFirewallScript ||
		script == windowsRDPEnableFirewallScript ||
		script == windowsRDPEnablePortScript ||
		script == windowsRDPEnableAddressScript ||
		script == windowsRDPEnableBindingScript ||
		script == windowsRDPVerifyDisabledScript ||
		script == windowsRDPFinalEnableScript ||
		script == windowsRDPVerifyEnabledScript {
		return true
	}
	return false
}

func allowedSystemctl(arguments []string) bool {
	if len(arguments) == 2 &&
		(arguments[0] == "start" || arguments[0] == "enable") {
		return arguments[1] == "ssh.service" || arguments[1] == "sshd.service"
	}
	if len(arguments) != 8 || arguments[0] != "show" ||
		(arguments[1] != "ssh.service" && arguments[1] != "sshd.service") {
		return false
	}
	return equalArguments(arguments[2:],
		"--no-pager",
		"--property=LoadState",
		"--property=ActiveState",
		"--property=UnitFileState",
		"--property=MainPID",
		"--property=ActiveEnterTimestampMonotonic",
	)
}

func allowedSC(arguments []string) bool {
	if len(arguments) == 2 && arguments[0] == "start" {
		return arguments[1] == "sshd" || arguments[1] == "TermService"
	}
	if len(arguments) == 4 && arguments[0] == "config" &&
		(arguments[1] == "sshd" || arguments[1] == "TermService") &&
		arguments[2] == "start=" {
		return arguments[3] == "demand"
	}
	return false
}

func allowedLsof(arguments []string) bool {
	if equalArguments(arguments, "-nP", "-iTCP:22", "-sTCP:LISTEN") {
		return true
	}
	if len(arguments) != 6 ||
		!equalArguments(arguments[:3], "-nP", "-a", "-p") ||
		!strings.HasPrefix(arguments[4], "-iTCP:") ||
		arguments[5] != "-sTCP:LISTEN" {
		return false
	}
	if _, err := strconv.ParseUint(arguments[3], 10, 64); err != nil {
		return false
	}
	port := strings.TrimPrefix(arguments[4], "-iTCP:")
	return port == "22" || port == "5900"
}

func equalArguments(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}

func linuxUnitName(service fixedService) string {
	if service == fixedLinuxSSHD {
		return "sshd.service"
	}
	return "ssh.service"
}

func windowsServiceName(service fixedService) string {
	if service == fixedWindowsSSH {
		return "sshd"
	}
	return "TermService"
}
