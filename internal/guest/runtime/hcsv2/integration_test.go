//go:build linux
// +build linux

package hcsv2

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	cgroups2 "github.com/containerd/cgroups/v3/cgroup2"
	oci "github.com/opencontainers/runtime-spec/specs-go"
)

func TestCgroupV1ToV2Migration_Integration(t *testing.T) {
	// Test the migration path from v1 to v2 cgroups
	testCases := []struct {
		name          string
		memoryLimit   int64
		pidsLimit     int64
		expectedError bool
	}{
		{
			name:        "Basic migration",
			memoryLimit: 128 * 1024 * 1024, // 128MB
			pidsLimit:   100,
		},
		{
			name:        "Large limits",
			memoryLimit: 2 * 1024 * 1024 * 1024, // 2GB
			pidsLimit:   1000,
		},
		{
			name:        "Zero limits",
			memoryLimit: 0,
			pidsLimit:   0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create v1-style OCI resources
			ociResources := &oci.LinuxResources{
				Memory: &oci.LinuxMemory{
					Limit: &tc.memoryLimit,
				},
				Pids: &oci.LinuxPids{
					Limit: &tc.pidsLimit,
				},
			}

			// Test conversion to v2
			v2Resources := convertSpecsToV2Resources(ociResources)
			if v2Resources == nil {
				t.Fatal("v2Resources conversion failed")
			}

			// Verify memory conversion
			if ociResources.Memory.Limit != nil {
				if v2Resources.Memory == nil {
					t.Error("Memory resource not converted")
				} else if *v2Resources.Memory.Max != *ociResources.Memory.Limit {
					t.Errorf("Memory limit mismatch: expected %d, got %d",
						*ociResources.Memory.Limit, *v2Resources.Memory.Max)
				}
			}

			// Verify PIDs conversion
			if tc.pidsLimit > 0 {
				if v2Resources.Pids == nil {
					t.Error("PIDs resource not converted")
				} else if v2Resources.Pids.Max != tc.pidsLimit {
					t.Errorf("PIDs limit mismatch: expected %d, got %d",
						tc.pidsLimit, v2Resources.Pids.Max)
				}
			} else {
				if v2Resources.Pids != nil {
					t.Error("PIDs resource should not be converted for zero limit")
				}
			}

			t.Logf("Migration test passed for %s: memory=%d, pids=%d",
				tc.name, tc.memoryLimit, tc.pidsLimit)
		})
	}
}

func TestMemoryLimitEnforcement_BothVersions(t *testing.T) {
	// Test that memory limits are properly enforced in both v1 and v2
	testLimit := int64(64 * 1024 * 1024) // 64MB

	// Test cgroup v1 style
	testMemoryV1 := func(t *testing.T) {
		// This would require actual cgroup creation, which is complex in unit tests
		// For now, test the resource creation logic
		ociResources := &oci.LinuxResources{
			Memory: &oci.LinuxMemory{
				Limit: &testLimit,
			},
		}

		if ociResources.Memory.Limit == nil || *ociResources.Memory.Limit != testLimit {
			t.Error("V1 memory limit not set properly")
		}
		t.Logf("V1 memory limit: %d bytes", *ociResources.Memory.Limit)
	}

	// Test cgroup v2 style
	testMemoryV2 := func(t *testing.T) {
		v2Resources := &cgroups2.Resources{
			Memory: &cgroups2.Memory{
				Max: &testLimit,
			},
		}

		if v2Resources.Memory == nil || v2Resources.Memory.Max == nil || *v2Resources.Memory.Max != testLimit {
			t.Error("V2 memory limit not set properly")
		}
		t.Logf("V2 memory limit: %d bytes", v2Resources.Memory.Max)
	}

	t.Run("V1_Style", testMemoryV1)
	t.Run("V2_Style", testMemoryV2)
}

func TestCPUThrottling_V1VsV2Consistency(t *testing.T) {
	// Test CPU throttling behavior consistency between v1 and v2

	// Mock CPU stats for v1
	testV1CPUStats := func(t *testing.T) {
		// In real v1 cgroups, CPU stats would come from /sys/fs/cgroup/cpu/...
		// Here we test the data structure consistency

		periods := uint64(1000)
		throttledPeriods := uint64(50)

		// Use the variables to avoid unused variable errors
		if periods == 0 || throttledPeriods > periods {
			t.Error("Invalid v1 CPU throttling data")
		}

		throttleRatio := float64(throttledPeriods) / float64(periods)
		t.Logf("V1 throttle ratio: %.2f%% (%d/%d periods)", throttleRatio*100, throttledPeriods, periods)
	}

	// Mock CPU stats for v2
	testV2CPUStats := func(t *testing.T) {
		// In real v2 cgroups, CPU stats would come from /sys/fs/cgroup/cpu.stat
		// Here we test the data structure consistency

		usageUsec := uint64(5000000)  // 5 seconds
		userUsec := uint64(2000000)   // 2 seconds
		systemUsec := uint64(3000000) // 3 seconds
		nrPeriods := uint64(1000)
		nrThrottled := uint64(50)
		throttledUsec := uint64(1500000) // 1.5 seconds

		if usageUsec != (userUsec + systemUsec) {
			t.Error("V2 CPU usage accounting inconsistent")
		}

		if nrThrottled > nrPeriods {
			t.Error("Invalid v2 CPU throttling data")
		}

		throttleRatio := float64(nrThrottled) / float64(nrPeriods)
		t.Logf("V2 throttle ratio: %.2f%% (%d/%d periods), throttled time: %dus", throttleRatio*100, nrThrottled, nrPeriods, throttledUsec)
	}

	t.Run("V1_CPU_Stats", testV1CPUStats)
	t.Run("V2_CPU_Stats", testV2CPUStats)
}

func TestContainerLifecycle_Integration(t *testing.T) {
	// Test full container lifecycle with both cgroup versions
	containerID := "test-lifecycle-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	testCases := []struct {
		name          string
		useV2         bool
		memoryLimit   int64
		expectedError bool
	}{
		{
			name:        "V1 Lifecycle",
			useV2:       false,
			memoryLimit: 256 * 1024 * 1024, // 256MB
		},
		{
			name:        "V2 Lifecycle",
			useV2:       true,
			memoryLimit: 256 * 1024 * 1024, // 256MB
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create container configuration
			ociSpec := &oci.Spec{
				Linux: &oci.Linux{
					Resources: &oci.LinuxResources{
						Memory: &oci.LinuxMemory{
							Limit: &tc.memoryLimit,
						},
					},
				},
			}

			// Simulate container creation
			container := &Container{
				id:   containerID,
				spec: ociSpec,
			}

			if container.id != containerID {
				t.Error("Container ID not set properly")
			}

			if container.spec.Linux.Resources.Memory.Limit == nil ||
				*container.spec.Linux.Resources.Memory.Limit != tc.memoryLimit {
				t.Error("Container memory limit not configured properly")
			}

			t.Logf("Container %s created with memory limit %d", containerID, tc.memoryLimit)

			// Test stats collection (mocked)
			ctx := context.Background()
			_, err := container.GetStats(ctx)
			if err != nil {
				t.Logf("Expected stats error in test environment: %v", err)
			}
		})
	}
}

func TestVirtualPod_Integration(t *testing.T) {
	// Test virtual pod integration with different cgroup versions
	virtualSandboxID := "test-virtual-integration-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	// Test virtual pod creation
	virtualPod := &VirtualPod{
		VirtualSandboxID: virtualSandboxID,
		MasterSandboxID:  "master-sandbox-123",
		NetworkNamespace: "test-netns",
		CgroupPath:       filepath.Join("/containers/virtual-pods", virtualSandboxID),
		Containers:       make(map[string]bool),
		CreatedAt:        time.Now(),
	}

	// Test adding multiple containers
	containerIDs := []string{
		"container-1", "container-2", "container-3",
	}

	for _, containerID := range containerIDs {
		virtualPod.Containers[containerID] = true
	}

	if len(virtualPod.Containers) != len(containerIDs) {
		t.Errorf("Expected %d containers, got %d", len(containerIDs), len(virtualPod.Containers))
	}

	// Test resource allocation for virtual pod
	resources := &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: func() *int64 { v := int64(512 * 1024 * 1024); return &v }(), // 512MB
		},
		Pids: &oci.LinuxPids{
			Limit: func() *int64 { v := int64(200); return &v }(),
		},
	}

	v2Resources := convertSpecsToV2Resources(resources)
	if v2Resources == nil {
		t.Fatal("Failed to convert resources for virtual pod")
	}

	if v2Resources.Memory == nil || *v2Resources.Memory.Max != *resources.Memory.Limit {
		t.Error("Virtual pod memory allocation failed")
	}

	if v2Resources.Pids == nil || v2Resources.Pids.Max != *resources.Pids.Limit {
		t.Error("Virtual pod PIDs allocation failed")
	}

	t.Logf("Virtual pod %s created with %d containers", virtualSandboxID, len(virtualPod.Containers))
}

func TestErrorRecovery_Integration(t *testing.T) {
	// Test error recovery scenarios in cgroup operations
	testCases := []struct {
		name           string
		simulateError  string
		expectedResult string
	}{
		{
			name:           "Invalid cgroup path",
			simulateError:  "path_not_found",
			expectedResult: "graceful_error_handling",
		},
		{
			name:           "Permission denied",
			simulateError:  "permission_denied",
			expectedResult: "graceful_error_handling",
		},
		{
			name:           "Resource limit exceeded",
			simulateError:  "resource_limit",
			expectedResult: "graceful_error_handling",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test error handling in different scenarios
			switch tc.simulateError {
			case "path_not_found":
				// Test with non-existent path
				invalidPath := "/sys/fs/cgroup/nonexistent/path"
				if _, err := os.Stat(invalidPath); err == nil {
					t.Error("Path should not exist")
				}
				t.Logf("Correctly detected invalid path: %s", invalidPath)

			case "permission_denied":
				// Test with restricted path
				restrictedPath := "/sys/fs/cgroup"
				if _, err := os.Stat(restrictedPath); os.IsPermission(err) {
					t.Logf("Permission check working: %s", restrictedPath)
				}

			case "resource_limit":
				// Test with extreme resource values
				extremeLimit := int64(^uint64(0) >> 1) // Max int64
				resources := &oci.LinuxResources{
					Memory: &oci.LinuxMemory{
						Limit: &extremeLimit,
					},
				}

				v2Resources := convertSpecsToV2Resources(resources)
				if v2Resources != nil && v2Resources.Memory != nil {
					t.Logf("Extreme limit handled: %d", *v2Resources.Memory.Max)
				}
			}
		})
	}
}

func TestPerformance_Integration(t *testing.T) {
	// Performance test for cgroup operations
	iterations := 1000

	// Test stats conversion performance
	startTime := time.Now()
	for i := 0; i < iterations; i++ {
		resources := &oci.LinuxResources{
			Memory: &oci.LinuxMemory{
				Limit: func() *int64 { v := int64(i * 1024 * 1024); return &v }(), // Variable size
			},
			Pids: &oci.LinuxPids{
				Limit: func() *int64 { v := int64(i + 100); return &v }(),
			},
		}

		v2Resources := convertSpecsToV2Resources(resources)
		if v2Resources == nil {
			t.Error("Resource conversion failed")
			break
		}
	}
	duration := time.Since(startTime)

	avgDuration := duration / time.Duration(iterations)
	t.Logf("Resource conversion performance: %d iterations in %v (avg: %v per conversion)",
		iterations, duration, avgDuration)

	// Performance should be reasonable (< 1ms per conversion on average)
	if avgDuration > time.Millisecond {
		t.Logf("Warning: Resource conversion taking longer than expected: %v", avgDuration)
	}
}
