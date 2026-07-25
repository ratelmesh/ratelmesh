package remoteaccess

import (
	"testing"
)

func TestGenerateLauncherMetadata(t *testing.T) {
	tests := []struct {
		name    string
		grant   *Grant
		wantURI string
		wantErr error
	}{
		{
			name:    "nil pointer",
			grant:   nil,
			wantURI: "",
			wantErr: ErrNilPointer,
		},
		{
			name: "macos ssh non-default port",
			grant: &Grant{
				Service: ServiceAdvertisement{
					Kind:         KindSSH,
					Port:         2222,
					Platform:     PlatformMacOS,
					Label:        "Mac",
					TargetNodeID: "n1",
					TargetMeshIP: "100.64.0.1",
				},
			},
			wantURI: "ssh://100.64.0.1:2222",
			wantErr: nil,
		},
		{
			name: "macos vnc",
			grant: &Grant{
				Service: ServiceAdvertisement{
					Kind:         KindVNC,
					Port:         5900,
					Platform:     PlatformMacOS,
					Label:        "Mac",
					TargetNodeID: "n1",
					TargetMeshIP: "100.64.0.1",
				},
			},
			wantURI: "vnc://100.64.0.1:5900",
			wantErr: nil,
		},
		{
			name: "windows rdp",
			grant: &Grant{
				Service: ServiceAdvertisement{
					Kind:         KindRDP,
					Port:         3389,
					Platform:     PlatformWindows,
					Label:        "Win",
					TargetNodeID: "n1",
					TargetMeshIP: "100.64.0.1",
				},
			},
			wantURI: "rdp://100.64.0.1:3389",
			wantErr: nil,
		},
		{
			name: "invalid ip fails validation",
			grant: &Grant{
				Service: ServiceAdvertisement{
					Kind:         KindSSH,
					Port:         22,
					Platform:     PlatformLinux,
					Label:        "Linux",
					TargetNodeID: "n1",
					TargetMeshIP: "not-an-ip; rm -rf /",
				},
			},
			wantURI: "",
			wantErr: ErrInvalidMeshIP,
		},
		{
			name: "ipv6 escaping",
			grant: &Grant{
				Service: ServiceAdvertisement{
					Kind:         KindVNC,
					Port:         5900,
					Platform:     PlatformLinux,
					Label:        "Linux",
					TargetNodeID: "n1",
					TargetMeshIP: "fd7a:115c:a1e0::1",
				},
			},
			wantURI: "vnc://[fd7a:115c:a1e0::1]:5900",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meta, err := GenerateLauncherMetadata(tt.grant)
			if err != tt.wantErr {
				t.Errorf("got error %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil {
				if meta.URI != tt.wantURI {
					t.Errorf("got URI %q, want %q", meta.URI, tt.wantURI)
				}
			}
		})
	}
}
