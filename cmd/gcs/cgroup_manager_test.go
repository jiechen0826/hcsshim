//go:build linux
// +build linux

package main

import (
	"testing"

	cgroups2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

func TestCgroupManagerInterface_Compatibility(t *testing.T) {
	// Test that both managers implement the CgroupManager interface
	var v1mgr CgroupManager = &V1Manager{}
	var v2mgr CgroupManager = &V2Manager{path: "/test/path"}

	if v1mgr == nil || v2mgr == nil {
		t.Fatal("Both managers should implement CgroupManager interface")
	}
}

func TestConvertToV2Resources_Basic(t *testing.T) {
	limit := int64(1024 * 1024 * 1024) // 1GB

	ociResources := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &limit,
		},
	}

	v2Resources := convertToV2Resources(ociResources)

	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil")
	}
	if v2Resources.Memory == nil {
		t.Fatal("v2Resources.Memory should not be nil")
	}
	if v2Resources.Memory.Max == nil || *v2Resources.Memory.Max != limit {
		t.Errorf("Expected memory max %d, got %v", limit, v2Resources.Memory.Max)
	}
}

func TestIsCgroupV2_Detection(t *testing.T) {
	// Test the cgroup version detection
	result1 := isCgroupV2()
	result2 := isCgroupV2()

	// Should be consistent
	if result1 != result2 {
		t.Error("isCgroupV2() should return consistent results")
	}

	t.Logf("Detected cgroup version: v%d", map[bool]int{false: 1, true: 2}[result1])
}

// Additional Error Handling and Edge Cases
func TestCgroupManager_InvalidPath(t *testing.T) {
	// Use a path that cannot be created due to read-only filesystem constraints
	v2mgr := &V2Manager{path: "/proc/nonexistent/path"}
	err := v2mgr.Create(1234)
	if err == nil {
		t.Error("Expected error for invalid cgroup path, got nil")
	} else {
		t.Logf("Expected error for invalid path: %v", err)
	}
}

func TestCgroupManager_PermissionDenied(t *testing.T) {
	// Test with root path that should require permissions
	v2mgr := &V2Manager{path: "/sys/fs/cgroup/test-permission-denied"}
	err := v2mgr.Create(1234)
	// Error is expected, just ensure it doesn't panic
	if err != nil {
		t.Logf("Expected permission error: %v", err)
	}
}

func TestConvertV2StatsToV1_InvalidInput(t *testing.T) {
	// Test with nil input
	result := convertV2StatsToV1Stats(nil)
	if result == nil {
		t.Error("convertV2StatsToV1Stats should handle nil input gracefully")
	}

	// Test with empty metrics
	emptyMetrics := &cgroups2stats.Metrics{}
	result = convertV2StatsToV1Stats(emptyMetrics)
	if result == nil {
		t.Error("convertV2StatsToV1Stats should handle empty metrics")
	}
}

func TestConvertToV2Resources_ExtremeLimits(t *testing.T) {
	// Test with maximum possible values
	maxLimit := int64(^uint64(0) >> 1) // Max int64
	ociResources := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &maxLimit,
		},
		Pids: &oci.LinuxPids{
			Limit: &maxLimit,
		},
	}

	v2Resources := convertToV2Resources(ociResources)
	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil")
	}

	// Test with zero values
	zeroLimit := int64(0)
	ociResourcesZero := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &zeroLimit,
		},
	}

	v2ResourcesZero := convertToV2Resources(ociResourcesZero)
	if v2ResourcesZero == nil || v2ResourcesZero.Memory == nil {
		t.Error("Should handle zero limit values")
	}
}
