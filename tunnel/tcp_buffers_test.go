package tunnel

import "testing"

func TestTCPBufferPresets(t *testing.T) {
	for _, tc := range []struct {
		name, preset, def, max        string
		wantMin, wantDefault, wantMax int
	}{
		{"bounded defaults", "", "", "", 65536, 256 << 10, 1 << 20},
		{"bounded custom", "", "1024", "2048", 65536, 1 << 20, 2 << 20},
		{"max raised to default", "", "2048", "256", 65536, 2 << 20, 2 << 20},
		{"invalid override", "", "16384", "65536", 65536, 256 << 10, 1 << 20},
		{"upstream ignores small overrides", "upstream", "1024", "1024", 4 << 20, 16 << 20, 64 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PAPERFLUX_TCP_BUFFER_PRESET", tc.preset)
			t.Setenv("PAPERFLUX_TCP_BUFFER_KIB", tc.def)
			t.Setenv("PAPERFLUX_TCP_BUFFER_MAX_KIB", tc.max)
			min, def, max := configuredTCPBufferRange()
			if min != tc.wantMin || def != tc.wantDefault || max != tc.wantMax {
				t.Fatalf("got %d/%d/%d", min, def, max)
			}
		})
	}
}
