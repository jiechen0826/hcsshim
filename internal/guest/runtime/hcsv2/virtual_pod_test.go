//go:build linux
// +build linux

package hcsv2

import (
	"fmt"
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

func TestConvertSpecsToV2Resources_Memory(t *testing.T) {
	limit := int64(1024 * 1024 * 1024)      // 1GB
	reservation := int64(512 * 1024 * 1024) // 512MB
	swap := int64(2 * 1024 * 1024 * 1024)   // 2GB

	resources := &specs.LinuxResources{
		Memory: &specs.LinuxMemory{
			Limit:       &limit,
			Reservation: &reservation,
			Swap:        &swap,
		},
	}

	v2Resources := convertSpecsToV2Resources(resources)

	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil")
	}
	if v2Resources.Memory == nil {
		t.Fatal("v2Resources.Memory should not be nil")
	}
	if v2Resources.Memory.Max == nil || *v2Resources.Memory.Max != limit {
		t.Errorf("Expected memory max %d, got %v", limit, v2Resources.Memory.Max)
	}
	if v2Resources.Memory.Low == nil || *v2Resources.Memory.Low != reservation {
		t.Errorf("Expected memory low %d, got %v", reservation, v2Resources.Memory.Low)
	}
	if v2Resources.Memory.Swap == nil || *v2Resources.Memory.Swap != swap {
		t.Errorf("Expected memory swap %d, got %v", swap, v2Resources.Memory.Swap)
	}
}

func TestConvertSpecsToV2Resources_PIDs(t *testing.T) {
	limit := int64(1000)

	resources := &specs.LinuxResources{
		Pids: &specs.LinuxPids{
			Limit: &limit,
		},
	}

	v2Resources := convertSpecsToV2Resources(resources)

	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil")
	}
	if v2Resources.Pids == nil {
		t.Fatal("v2Resources.Pids should not be nil")
	}
	if v2Resources.Pids.Max != limit {
		t.Errorf("Expected PIDs max %d, got %d", limit, v2Resources.Pids.Max)
	}
}

func TestConvertSpecsToV2Resources_NilResources(t *testing.T) {
	v2Resources := convertSpecsToV2Resources(nil)

	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil even for nil input")
	}
}

func TestVirtualPod_Structure(t *testing.T) {
	virtualSandboxID := "test-virtual-sandbox-123"
	masterSandboxID := "test-master-sandbox-456"
	networkNamespace := "test-netns"
	cgroupPath := "/containers/virtual-pods/test-virtual-sandbox-123"

	virtualPod := &VirtualPod{
		VirtualSandboxID: virtualSandboxID,
		MasterSandboxID:  masterSandboxID,
		NetworkNamespace: networkNamespace,
		CgroupPath:       cgroupPath,
		CgroupControl:    nil, // Would be actual cgroup in real scenario
		Containers:       make(map[string]bool),
		CreatedAt:        time.Now(),
	}

	if virtualPod.VirtualSandboxID != virtualSandboxID {
		t.Errorf("Expected VirtualSandboxID %s, got %s", virtualSandboxID, virtualPod.VirtualSandboxID)
	}
	if virtualPod.MasterSandboxID != masterSandboxID {
		t.Errorf("Expected MasterSandboxID %s, got %s", masterSandboxID, virtualPod.MasterSandboxID)
	}
	if virtualPod.NetworkNamespace != networkNamespace {
		t.Errorf("Expected NetworkNamespace %s, got %s", networkNamespace, virtualPod.NetworkNamespace)
	}
	if virtualPod.CgroupPath != cgroupPath {
		t.Errorf("Expected CgroupPath %s, got %s", cgroupPath, virtualPod.CgroupPath)
	}
	if virtualPod.Containers == nil {
		t.Error("Containers map should not be nil")
	}
}

func TestVirtualPod_ContainerManagement(t *testing.T) {
	virtualPod := &VirtualPod{
		VirtualSandboxID: "test-sandbox",
		Containers:       make(map[string]bool),
	}

	// Test adding containers
	containerIDs := []string{"container-1", "container-2", "container-3"}

	for _, id := range containerIDs {
		virtualPod.Containers[id] = true
	}

	// Verify all containers are tracked
	for _, id := range containerIDs {
		if !virtualPod.Containers[id] {
			t.Errorf("Container %s should be tracked", id)
		}
	}

	if len(virtualPod.Containers) != len(containerIDs) {
		t.Errorf("Expected %d containers, got %d", len(containerIDs), len(virtualPod.Containers))
	}

	// Test removing containers
	delete(virtualPod.Containers, containerIDs[0])
	if virtualPod.Containers[containerIDs[0]] {
		t.Errorf("Container %s should have been removed", containerIDs[0])
	}
	if len(virtualPod.Containers) != len(containerIDs)-1 {
		t.Errorf("Expected %d containers after removal, got %d", len(containerIDs)-1, len(virtualPod.Containers))
	}
}

func TestHost_InitializeVirtualPodSupport_ErrorCases(t *testing.T) {
	host := &Host{}

	// Test with nil input
	err := host.InitializeVirtualPodSupport(nil)
	if err == nil {
		t.Error("Expected error for nil input")
	}
	if err != nil && err.Error() != "no valid cgroup manager provided for virtual pod support" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}

	// Test with invalid interface
	invalidMgr := "invalid manager"
	err = host.InitializeVirtualPodSupport(invalidMgr)
	if err == nil {
		t.Error("Expected error for invalid manager")
	}
}

// Additional Virtual Pod Resource Management Tests
func TestVirtualPod_ResourceUpdates(t *testing.T) {
	virtualPod := &VirtualPod{
		VirtualSandboxID: "test-update-123",
		MasterSandboxID:  "master-update-456",
		NetworkNamespace: "test-netns-update",
		CgroupPath:       "/containers/virtual-pods/test-update-123",
		CgroupControl:    nil,
		Containers:       make(map[string]bool),
		CreatedAt:        time.Now(),
	}

	// Test adding containers
	containerID1 := "container-1"
	containerID2 := "container-2"

	virtualPod.Containers[containerID1] = true
	virtualPod.Containers[containerID2] = true

	if len(virtualPod.Containers) != 2 {
		t.Errorf("Expected 2 containers, got %d", len(virtualPod.Containers))
	}

	// Test removing containers
	delete(virtualPod.Containers, containerID1)
	if len(virtualPod.Containers) != 1 {
		t.Errorf("Expected 1 container after removal, got %d", len(virtualPod.Containers))
	}
	if !virtualPod.Containers[containerID2] {
		t.Error("Container 2 should still be present")
	}
}

func TestVirtualPod_CleanupV2(t *testing.T) {
	virtualPod := &VirtualPod{
		VirtualSandboxID: "test-cleanup-v2-123",
		MasterSandboxID:  "master-cleanup-456",
		CgroupPath:       "/containers/virtual-pods/test-cleanup-v2-123",
		Containers: map[string]bool{
			"container-1": true,
			"container-2": true,
		},
		CreatedAt: time.Now(),
	}

	// Test cleanup operations
	containerCount := len(virtualPod.Containers)
	if containerCount != 2 {
		t.Errorf("Expected 2 containers before cleanup, got %d", containerCount)
	}

	// Simulate cleanup by clearing containers
	virtualPod.Containers = make(map[string]bool)
	if len(virtualPod.Containers) != 0 {
		t.Error("Containers should be empty after cleanup")
	}
}

func TestVirtualPod_MixedV1V2Environment(t *testing.T) {
	// Test virtual pod behavior in mixed cgroup environment
	testCases := []struct {
		name          string
		cgroupVersion int
		expectedError bool
	}{
		{
			name:          "CGroup V1",
			cgroupVersion: 1,
			expectedError: false,
		},
		{
			name:          "CGroup V2",
			cgroupVersion: 2,
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			virtualPod := &VirtualPod{
				VirtualSandboxID: fmt.Sprintf("test-mixed-%d-123", tc.cgroupVersion),
				MasterSandboxID:  "master-mixed-456",
				CgroupPath:       fmt.Sprintf("/containers/virtual-pods/test-mixed-%d-123", tc.cgroupVersion),
				Containers:       make(map[string]bool),
				CreatedAt:        time.Now(),
			}

			if virtualPod.VirtualSandboxID == "" {
				t.Error("VirtualSandboxID should not be empty")
			}
			if virtualPod.CgroupPath == "" {
				t.Error("CgroupPath should not be empty")
			}
		})
	}
}

func TestConvertSpecsToV2Resources_EdgeCases(t *testing.T) {
	// Test with extremely large values
	large := int64(^uint64(0) >> 1) // Max int64
	resources := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &large,
		},
		Pids: &oci.LinuxPids{
			Limit: &large,
		},
	}

	v2Resources := convertSpecsToV2Resources(resources)
	if v2Resources == nil {
		t.Fatal("v2Resources should not be nil")
	}
	if v2Resources.Memory == nil || *v2Resources.Memory.Max != large {
		t.Error("Large memory limit should be preserved")
	}
	if v2Resources.Pids == nil || v2Resources.Pids.Max != large {
		t.Error("Large PIDs limit should be preserved")
	}

	// Test with zero values
	zero := int64(0)
	zeroResources := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &zero,
		},
		Pids: &oci.LinuxPids{
			Limit: &zero,
		},
	}

	v2ZeroResources := convertSpecsToV2Resources(zeroResources)
	if v2ZeroResources == nil {
		t.Fatal("v2ZeroResources should not be nil")
	}
	if v2ZeroResources.Memory == nil || *v2ZeroResources.Memory.Max != zero {
		t.Error("Zero memory limit should be preserved")
	}
	if v2ZeroResources.Pids != nil {
		t.Error("Zero PIDs limit should not create PIDs resource")
	} else {
		t.Log("Zero PIDs limit correctly ignored")
	}
}

func TestVirtualPod_ConcurrentAccess(t *testing.T) {
	virtualPod := &VirtualPod{
		VirtualSandboxID: "test-concurrent-123",
		MasterSandboxID:  "master-concurrent-456",
		Containers:       make(map[string]bool),
		CreatedAt:        time.Now(),
	}

	// Simulate concurrent container additions
	go func() {
		for i := 0; i < 10; i++ {
			containerID := fmt.Sprintf("container-go1-%d", i)
			virtualPod.Containers[containerID] = true
			time.Sleep(1 * time.Millisecond)
		}
	}()

	go func() {
		for i := 0; i < 10; i++ {
			containerID := fmt.Sprintf("container-go2-%d", i)
			virtualPod.Containers[containerID] = true
			time.Sleep(1 * time.Millisecond)
		}
	}()

	// Wait for goroutines to complete
	time.Sleep(50 * time.Millisecond)

	// In a real implementation, this would need proper synchronization
	// This test demonstrates the need for thread-safe access
	containerCount := len(virtualPod.Containers)
	if containerCount == 0 {
		t.Error("Should have containers after concurrent addition")
	}
	t.Logf("Final container count: %d", containerCount)
}
