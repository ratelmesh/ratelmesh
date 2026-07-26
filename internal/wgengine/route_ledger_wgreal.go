//go:build wgreal

package wgengine

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/ratelmesh/ratelmesh/internal/atomicfile"
)

const routeLedgerFile = "route-owners-v1.json"

type persistedRouteOwner struct {
	Prefix         string `json:"prefix"`
	Gateway        string `json:"gateway,omitempty"`
	Device         string `json:"device,omitempty"`
	Kind           uint8  `json:"kind"`
	Windows        bool   `json:"windows,omitempty"`
	InterfaceIndex string `json:"interfaceIndex,omitempty"`
	NextHop        string `json:"nextHop,omitempty"`
	Pin            bool   `json:"pin,omitempty"`
}

type persistedRouteLedger struct {
	Version int                   `json:"version"`
	Routes  []persistedRouteOwner `json:"routes"`
}

func (e *RealEngine) PreparePersistentCleanup(stateDir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if stateDir == "" {
		return errors.New("wgengine: persistent cleanup requires a state directory")
	}
	e.routeLedgerPath = filepath.Join(stateDir, routeLedgerFile)
	data, err := os.ReadFile(e.routeLedgerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("wgengine: read route owner ledger: %w", err)
	}
	var ledger persistedRouteLedger
	if err := json.Unmarshal(data, &ledger); err != nil || ledger.Version != 1 {
		return fmt.Errorf("wgengine: invalid route owner ledger")
	}
	for _, record := range ledger.Routes {
		prefix, err := netip.ParsePrefix(record.Prefix)
		if err != nil {
			return fmt.Errorf("wgengine: invalid owned prefix %q: %w", record.Prefix, err)
		}
		if record.Windows {
			owner := windowsManagedRoute{prefix: prefix, interfaceIndex: record.InterfaceIndex, nextHop: record.NextHop}
			if err := e.removeWindowsRoute(owner); err != nil {
				return fmt.Errorf("wgengine: reconcile owned Windows route %s: %w", prefix, err)
			}
			continue
		}
		var gateway netip.Addr
		if record.Gateway != "" {
			gateway, err = netip.ParseAddr(record.Gateway)
			if err != nil {
				return fmt.Errorf("wgengine: invalid owned gateway %q: %w", record.Gateway, err)
			}
		}
		owner := unixManagedRoute{prefix: prefix, gateway: gateway, device: record.Device, kind: unixRouteKind(record.Kind)}
		if err := deleteUnixManagedRoute(owner); err != nil && !routeDeleteNotFound(err) {
			exists, verifyErr := unixManagedRouteExists(owner)
			if verifyErr != nil || exists {
				return errors.Join(fmt.Errorf("wgengine: reconcile owned route %s: %w", prefix, err), verifyErr)
			}
		}
	}
	return e.persistRouteLedgerLocked()
}

func (e *RealEngine) persistRouteLedgerLocked() error {
	if e.routeLedgerPath == "" {
		// Standalone engine tests and embedders may not use daemon persistence.
		// ratelmeshd always initializes this before Up.
		return nil
	}
	ledger := persistedRouteLedger{Version: 1}
	for prefix, owner := range e.routeOwners {
		record := persistedRouteOwner{Prefix: prefix.String(), Device: owner.device, Kind: uint8(owner.kind)}
		if owner.gateway.IsValid() {
			record.Gateway = owner.gateway.String()
		}
		ledger.Routes = append(ledger.Routes, record)
	}
	for _, owner := range e.pinOwners {
		record := persistedRouteOwner{Prefix: owner.prefix.String(), Device: owner.device, Kind: uint8(owner.kind), Pin: true}
		if owner.gateway.IsValid() {
			record.Gateway = owner.gateway.String()
		}
		ledger.Routes = append(ledger.Routes, record)
	}
	for _, owner := range e.windowsRoutes {
		ledger.Routes = append(ledger.Routes, persistedRouteOwner{
			Prefix: owner.prefix.String(), Windows: true,
			InterfaceIndex: owner.interfaceIndex, NextHop: owner.nextHop,
		})
	}
	if len(ledger.Routes) == 0 {
		err := os.Remove(e.routeLedgerPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	data, err := json.Marshal(ledger)
	if err != nil {
		return err
	}
	return atomicfile.WriteFile(e.routeLedgerPath, append(data, '\n'))
}
