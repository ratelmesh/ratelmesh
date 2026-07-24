// Command ratelmesh is the RatelMesh command-line front-end (DESIGN.md §3.4). It talks
// to the local ratelmeshd daemon over its unix socket. M1 implements `status` and
// `exit list`; `up`/`down` and `exit use` arrive with the exit milestone.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/ratelmesh/ratelmesh/internal/daemon"
	"github.com/ratelmesh/ratelmesh/internal/i18n"
	"github.com/ratelmesh/ratelmesh/internal/types"
)

// tr is the process printer, localized from the environment (DESIGN.md §9.3:
// follow the OS locale, overridable via RATELMESH_LANG).
var tr = i18n.NewPrinter(pickLocale())

func pickLocale() string {
	for _, env := range []string{"RATELMESH_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "en"
}

func main() {
	args, language, err := parseGlobalOptions(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratelmesh: %v\n\n", err)
		usage()
		os.Exit(2)
	}
	if language != "" {
		tr = i18n.NewPrinter(language)
	}
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	sock := defaultSocket()

	switch args[0] {
	case "status":
		cmdStatus(sock, hasFlag(args[1:], "--json"))
	case "exit":
		cmdExit(sock, args[1:])
	case "dns":
		cmdDNS(sock, args[1:])
	case "version":
		fmt.Println("ratelmesh (RatelMesh) — M1 dev build")
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "ratelmesh: unknown command %q\n\n", args[0])
		usage()
		os.Exit(2)
	}
}

func cmdStatus(sock string, asJSON bool) {
	st, err := daemon.FetchStatus(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratelmesh: cannot reach ratelmeshd at %s: %v\n", sock, err)
		fmt.Fprintln(os.Stderr, "is the daemon running? start it with: ratelmeshd")
		os.Exit(1)
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(st)
		return
	}

	fmt.Println(tr.T("status.state", i18n.V("state", string(st.State))))
	fmt.Println(tr.T("status.coord", i18n.V("coord", st.CoordURL)))
	if st.Self.MeshIP != "" {
		fmt.Println(tr.T("status.self",
			i18n.V("ip", st.Self.MeshIP), i18n.V("name", st.Self.Name), i18n.V("key", st.Self.KeyShort)))
	}
	if st.ActiveExit != "" {
		fmt.Println(tr.T("status.exit.active", i18n.V("name", st.ActiveExit)))
	} else if st.SelectedExit != "" {
		fmt.Println(tr.T("status.exit.connecting", i18n.V("name", st.SelectedExit)))
	} else {
		fmt.Println(tr.T("status.exit.none"))
	}
	if st.KillSwitch {
		fmt.Println(tr.T("status.killswitch.armed"))
	} else {
		fmt.Println(tr.T("status.killswitch.off"))
	}
	if st.DNS != "" {
		fmt.Println(tr.T("status.dns", i18n.V("resolver", st.DNS)))
	}
	fmt.Println(tr.T("status.netmap", i18n.V("version", st.Version), i18n.V("count", len(st.Peers))))
	fmt.Println()

	if len(st.Peers) == 0 {
		fmt.Println(tr.T("status.nopeers"))
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, tr.T("status.peers.header"))
	for _, p := range st.Peers {
		online := tr.T("common.no")
		if p.Online {
			online = tr.T("common.yes")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			p.MeshIP, p.Name, p.Role, p.PathType, online, p.KeyShort)
	}
	_ = tw.Flush()
}

func cmdExit(sock string, args []string) {
	if len(args) == 0 {
		exitUsage()
		os.Exit(2)
	}
	switch args[0] {
	case "list":
		exitList(sock)
	case "use":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: ratelmesh exit use <name|mesh-ip>")
			os.Exit(2)
		}
		if err := daemon.UseExit(sock, args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "ratelmesh: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(tr.T("exit.using", i18n.V("name", args[1])))
		printCurrentExit(sock)
	case "clear", "none":
		if err := daemon.ClearExit(sock); err != nil {
			fmt.Fprintf(os.Stderr, "ratelmesh: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(tr.T("exit.cleared"))
		printCurrentExit(sock)
	default:
		exitUsage()
		os.Exit(2)
	}
}

func exitList(sock string) {
	st, err := daemon.FetchStatus(sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratelmesh: cannot reach ratelmeshd: %v\n", err)
		os.Exit(1)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, tr.T("exit.list.header"))
	found := false
	for _, p := range st.Peers {
		if p.Role == types.RoleExit {
			found = true
			online := tr.T("common.no")
			if p.Online {
				online = tr.T("common.yes")
			}
			active := ""
			if p.Name == st.ActiveExit {
				active = tr.T("exit.list.active")
			} else if p.Name == st.SelectedExit {
				active = tr.T("exit.list.connecting")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.MeshIP, p.Name, online, active)
		}
	}
	_ = tw.Flush()
	if !found {
		fmt.Println(tr.T("exit.none"))
	}
}

func printCurrentExit(sock string) {
	st, err := daemon.FetchStatus(sock)
	if err != nil {
		return
	}
	if st.ActiveExit != "" {
		fmt.Println(tr.T("status.exit.active", i18n.V("name", st.ActiveExit)))
		return
	}
	if st.SelectedExit != "" {
		fmt.Println(tr.T("status.exit.connecting", i18n.V("name", st.SelectedExit)))
		return
	}
	fmt.Println(tr.T("status.exit.none"))
}

func exitUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  ratelmesh exit list            list available exit nodes
  ratelmesh exit use <name>      route all traffic through an exit node
  ratelmesh exit clear           resume direct egress`)
}

func cmdDNS(sock string, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ratelmesh dns <name>   resolve a MagicDNS name (e.g. laptop.alice.ratelmesh.net)")
		os.Exit(2)
	}
	ip, err := daemon.Resolve(sock, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ratelmesh: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(ip)
}

func defaultSocket() string { return daemon.DefaultSocketPath() }

func hasFlag(args []string, f string) bool {
	for _, a := range args {
		if a == f {
			return true
		}
	}
	return false
}

func parseGlobalOptions(args []string) (remaining []string, language string, err error) {
	for len(args) > 0 {
		switch {
		case args[0] == "--lang":
			if len(args) < 2 || args[1] == "" {
				return nil, "", fmt.Errorf("--lang requires a language such as en, zh-Hans or ja")
			}
			language = args[1]
			args = args[2:]
		case strings.HasPrefix(args[0], "--lang=") && len(args[0]) > len("--lang="):
			language = args[0][len("--lang="):]
			args = args[1:]
		default:
			return args, language, nil
		}
	}
	return args, language, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `ratelmesh — RatelMesh CLI

Usage:
  ratelmesh --lang <locale> ... select en, zh-Hans or ja for this command
  ratelmesh status [--json]     show mesh state and peers
  ratelmesh exit list           list available exit nodes
  ratelmesh version             print version

Set RATELMESH_LANG to keep a language choice across commands.
The daemon (ratelmeshd) must be running. Socket: $RATELMESH_SOCKET or <config>/ratelmesh/ratelmeshd.sock`)
}
