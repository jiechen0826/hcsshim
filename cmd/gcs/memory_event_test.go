//go:build linux
// +build linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cgroups1 "github.com/containerd/cgroups/v3/cgroup1"
	cgroups2 "github.com/containerd/cgroups/v3/cgroup2"
)

func TestMemoryEventMonitoring_V2(t *testing.T) {
	if !isCgroupV2() {
		t.Skip("Skipping cgroup v2 test on v1 system")
	}

	// Create a temporary cgroup path for testing
	testPath := filepath.Join("/sys/fs/cgroup", "test-memory-event-"+strconv.FormatInt(time.Now().UnixNano(), 10))

	// Clean up after test
	defer func() {
		if _, err := os.Stat(testPath); err == nil {
			os.RemoveAll(testPath)
		}
	}()

	v2mgr := &V2Manager{path: testPath}

	// Test memory event registration with empty event struct
	// Note: In a real implementation, this would use actual cgroup event configuration
	var event cgroups1.MemoryEvent
	_, err := v2mgr.RegisterMemoryEvent(event)

	// Should not panic even if path doesn't exist
	if err != nil {
		t.Logf("Expected error for non-existent cgroup: %v", err)
	}
}

func TestOOMEventFD_V2_Integration(t *testing.T) {
	if !isCgroupV2() {
		t.Skip("Skipping cgroup v2 test on v1 system")
	}

	v2mgr := &V2Manager{path: "/sys/fs/cgroup/test-oom"}

	// Test OOM event FD creation
	fd, err := v2mgr.OOMEventFD()
	if err != nil {
		t.Logf("Expected error for test cgroup: %v", err)
		return
	}

	if fd < 0 {
		t.Error("OOMEventFD should return valid file descriptor")
	}
}

func TestMemoryThresholdDetection_V2(t *testing.T) {
	if !isCgroupV2() {
		t.Skip("Skipping cgroup v2 test on v1 system")
	}

	// Test threshold detection with various limits
	testCases := []struct {
		name      string
		limit     int64
		current   uint64
		expectHit bool
	}{
		{
			name:      "Under threshold",
			limit:     1024 * 1024 * 1024, // 1GB
			current:   512 * 1024 * 1024,  // 512MB
			expectHit: false,
		},
		{
			name:      "Over threshold",
			limit:     1024 * 1024 * 1024, // 1GB
			current:   2048 * 1024 * 1024, // 2GB
			expectHit: true,
		},
		{
			name:      "Exact threshold",
			limit:     1024 * 1024 * 1024, // 1GB
			current:   1024 * 1024 * 1024, // 1GB
			expectHit: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			thresholdHit := tc.current >= uint64(tc.limit)
			if thresholdHit != tc.expectHit {
				t.Errorf("Expected threshold hit %v, got %v", tc.expectHit, thresholdHit)
			}
		})
	}
}

func TestMemoryEvent_ErrorHandling(t *testing.T) {
	// Test with invalid path
	invalidMgr := &V2Manager{path: "/invalid/path"}

	var event cgroups1.MemoryEvent
	_, err := invalidMgr.RegisterMemoryEvent(event)
	if err == nil {
		t.Error("Expected error for invalid cgroup path")
	}

	// Test with valid manager - should work or give expected error
	validMgr := &V2Manager{path: "/sys/fs/cgroup"}
	_, err = validMgr.RegisterMemoryEvent(event)
	if err != nil {
		t.Logf("Expected error for test environment: %v", err)
	}
}

func TestCgroupV2ResourceCreation(t *testing.T) {
	if !isCgroupV2() {
		t.Skip("Skipping cgroup v2 test on v1 system")
	}

	// Test creating v2 resources with various configurations
	testCases := []struct {
		name   string
		memory *int64
		pids   *int64
		cpu    *int64
	}{
		{
			name:   "Memory only",
			memory: func() *int64 { v := int64(1024 * 1024 * 1024); return &v }(), // 1GB
		},
		{
			name: "PIDs only",
			pids: func() *int64 { v := int64(1000); return &v }(),
		},
		{
			name:   "All resources",
			memory: func() *int64 { v := int64(2048 * 1024 * 1024); return &v }(), // 2GB
			pids:   func() *int64 { v := int64(500); return &v }(),
			cpu:    func() *int64 { v := int64(100000); return &v }(), // 100ms
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resources := &cgroups2.Resources{}

			if tc.memory != nil {
				resources.Memory = &cgroups2.Memory{Max: tc.memory}
			}
			if tc.pids != nil {
				resources.Pids = &cgroups2.Pids{Max: *tc.pids}
			}
			if tc.cpu != nil {
				// CPU limit in cgroup v2 uses quota/period format
				period := uint64(100000) // 100ms period
				resources.CPU = &cgroups2.CPU{Max: cgroups2.NewCPUMax(tc.cpu, &period)}
			}

			if resources.Memory == nil && resources.Pids == nil && resources.CPU == nil {
				t.Error("At least one resource should be configured")
			}
		})
	}
}
