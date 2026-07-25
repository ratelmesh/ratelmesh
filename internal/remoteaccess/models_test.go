package remoteaccess

import (
	"testing"
	"time"
)

func TestServiceAdvertisement_Validate(t *testing.T) {
	var nilAdv *ServiceAdvertisement
	if err := nilAdv.Validate(); err != ErrNilPointer {
		t.Errorf("expected ErrNilPointer, got %v", err)
	}

	tests := []struct {
		name    string
		adv     ServiceAdvertisement
		wantErr error
	}{
		{
			name: "valid ssh macos",
			adv: ServiceAdvertisement{
				Kind:         KindSSH,
				Port:         22,
				Platform:     PlatformMacOS,
				Label:        "Mac Mini SSH",
				TargetNodeID: "node1",
				TargetMeshIP: "100.64.0.1",
			},
			wantErr: nil,
		},
		{
			name: "valid rdp windows",
			adv: ServiceAdvertisement{
				Kind:         KindRDP,
				Port:         3389,
				Platform:     PlatformWindows,
				Label:        "Win PC",
				TargetNodeID: "node2",
				TargetMeshIP: "100.64.12.34",
			},
			wantErr: nil,
		},
		{
			name: "valid ipv6 ula",
			adv: ServiceAdvertisement{
				Kind:         KindSSH,
				Port:         22,
				Platform:     PlatformLinux,
				Label:        "IPv6 Server",
				TargetNodeID: "node3",
				TargetMeshIP: "fd7a:115c:a1e0::1",
			},
			wantErr: nil,
		},
		{
			name: "invalid kind for platform",
			adv: ServiceAdvertisement{
				Kind:         KindVNC,
				Port:         5900,
				Platform:     PlatformWindows, // Windows does not support VNC in our compat matrix
				Label:        "VNC Server",
				TargetNodeID: "node1",
				TargetMeshIP: "100.64.0.1",
			},
			wantErr: ErrInvalidServiceKind,
		},
		{
			name: "mobile cannot advertise remote desktop service",
			adv: ServiceAdvertisement{
				Kind:         KindSSH,
				Port:         22,
				Platform:     PlatformAndroid,
				Label:        "SSH",
				TargetNodeID: "phone",
				TargetMeshIP: "100.64.0.8",
			},
			wantErr: ErrInvalidPlatform,
		},
		{
			name: "invalid ip (public)",
			adv: ServiceAdvertisement{
				Kind:         KindSSH,
				Port:         22,
				Platform:     PlatformLinux,
				Label:        "SSH Server",
				TargetNodeID: "node1",
				TargetMeshIP: "8.8.8.8",
			},
			wantErr: ErrInvalidMeshIP,
		},
		{
			name: "control chars in label",
			adv: ServiceAdvertisement{
				Kind:         KindSSH,
				Port:         22,
				Platform:     PlatformLinux,
				Label:        "SSH\nServer",
				TargetNodeID: "node1",
				TargetMeshIP: "100.64.0.1",
			},
			wantErr: ErrInvalidID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.adv.Validate()
			if err != tt.wantErr {
				t.Errorf("got error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGrant_Validate(t *testing.T) {
	now := time.Now()

	var nilGrant *Grant
	if err := nilGrant.Validate(now); err != ErrNilPointer {
		t.Errorf("expected ErrNilPointer, got %v", err)
	}

	validService := ServiceAdvertisement{
		Kind:         KindSSH,
		Port:         22,
		Platform:     PlatformLinux,
		Label:        "Linux Box",
		TargetNodeID: "node1",
		TargetMeshIP: "100.64.0.1",
	}

	tests := []struct {
		name    string
		grant   Grant
		now     time.Time
		wantErr error
	}{
		{
			name: "valid grant",
			grant: Grant{
				ID:            "g1",
				TenantID:      "t1",
				GrantorID:     "u1",
				GranteeID:     "u2",
				GranteeMeshIP: "100.64.0.2",
				PolicyVersion: 1,
				Service:       validService,
				IssuedAt:      now.Add(-time.Hour),
				NotBefore:     now.Add(-time.Hour),
				ExpiresAt:     now.Add(time.Hour),
			},
			now:     now,
			wantErr: nil,
		},
		{
			name: "zero timestamp",
			grant: Grant{
				ID:            "g1",
				TenantID:      "t1",
				GrantorID:     "u1",
				GranteeID:     "u2",
				GranteeMeshIP: "100.64.0.2",
				PolicyVersion: 1,
				Service:       validService,
				IssuedAt:      time.Time{},
				NotBefore:     now.Add(-time.Hour),
				ExpiresAt:     now.Add(time.Hour),
			},
			now:     now,
			wantErr: ErrInvalidChronology,
		},
		{
			name: "issued after not before",
			grant: Grant{
				ID:            "g1",
				TenantID:      "t1",
				GrantorID:     "u1",
				GranteeID:     "u2",
				GranteeMeshIP: "100.64.0.2",
				PolicyVersion: 1,
				Service:       validService,
				IssuedAt:      now.Add(time.Hour),
				NotBefore:     now,
				ExpiresAt:     now.Add(2 * time.Hour),
			},
			now:     now,
			wantErr: ErrInvalidChronology,
		},
		{
			name: "not before equal to expires at",
			grant: Grant{
				ID:            "g1",
				TenantID:      "t1",
				GrantorID:     "u1",
				GranteeID:     "u2",
				GranteeMeshIP: "100.64.0.2",
				PolicyVersion: 1,
				Service:       validService,
				IssuedAt:      now.Add(-time.Hour),
				NotBefore:     now,
				ExpiresAt:     now,
			},
			now:     now,
			wantErr: ErrInvalidChronology,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.grant.Validate(tt.now)
			if err != tt.wantErr {
				t.Errorf("got error %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
