//go:build linux
// +build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	cgroups1 "github.com/containerd/cgroups/v3/cgroup1"
	cgroups1stats "github.com/containerd/cgroups/v3/cgroup1/stats"
	cgroups2 "github.com/containerd/cgroups/v3/cgroup2"
	cgroups2stats "github.com/containerd/cgroups/v3/cgroup2/stats"
	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"
	"golang.org/x/sys/unix"

	"github.com/Microsoft/hcsshim/internal/guest/bridge"
	"github.com/Microsoft/hcsshim/internal/guest/kmsg"
	"github.com/Microsoft/hcsshim/internal/guest/runtime/hcsv2"
	"github.com/Microsoft/hcsshim/internal/guest/runtime/runc"
	"github.com/Microsoft/hcsshim/internal/guest/transport"
	"github.com/Microsoft/hcsshim/internal/guestpath"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/oc"
	"github.com/Microsoft/hcsshim/internal/version"
	"github.com/Microsoft/hcsshim/pkg/securitypolicy"
)

// isCgroupV2 checks if cgroup v2 is available on the system
func isCgroupV2() bool {
	// Check if cgroup v2 was disabled via kernel parameter
	if isCgroupV2DisabledByKernel() {
		return false
	}

	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// isCgroupV2DisabledByKernel checks if cgroup v2 was disabled via kernel parameters
func isCgroupV2DisabledByKernel() bool {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}

	cmdlineStr := string(cmdline)
	if strings.Contains(cmdlineStr, "cgroup_no_v2=all") {
		logrus.Info("cgroup v2 disabled by kernel parameter cgroup_no_v2=all")
		return true
	}

	return false
}

// CgroupManager provides a unified interface for cgroup v1 and v2 operations
type CgroupManager interface {
	Create(pid int) error
	Delete() error
	Stats() (*cgroups1stats.Metrics, error)
	Update(resources *oci.LinuxResources) error
	AddTask(pid int) error
	Add(process cgroups1.Process, names ...cgroups1.Name) error
	RegisterMemoryEvent(event cgroups1.MemoryEvent) (uintptr, error)
	OOMEventFD() (uintptr, error)
	// GetV1Cgroup returns the underlying v1 cgroup if available, nil for v2
	GetV1Cgroup() cgroups1.Cgroup
	// GetV2Manager returns the underlying v2 manager if available, nil for v1
	GetV2Manager() *cgroups2.Manager
}

// V1Manager wraps cgroup v1 operations
type V1Manager struct {
	cg cgroups1.Cgroup
}

func (v *V1Manager) Create(pid int) error {
	return v.cg.Add(cgroups1.Process{Pid: pid})
}

func (v *V1Manager) Stats() (*cgroups1stats.Metrics, error) {
	return v.cg.Stat(cgroups1.IgnoreNotExist)
}

func (v *V1Manager) Update(resources *oci.LinuxResources) error {
	return v.cg.Update(resources)
}

func (v *V1Manager) AddTask(pid int) error {
	return v.cg.AddTask(cgroups1.Process{Pid: pid})
}

func (v *V1Manager) Add(process cgroups1.Process, names ...cgroups1.Name) error {
	return v.cg.Add(process, names...)
}

func (v *V1Manager) Delete() error {
	return v.cg.Delete()
}

func (v *V1Manager) RegisterMemoryEvent(event cgroups1.MemoryEvent) (uintptr, error) {
	return v.cg.RegisterMemoryEvent(event)
}

func (v *V1Manager) OOMEventFD() (uintptr, error) {
	return v.cg.OOMEventFD()
}

func (v *V1Manager) GetV1Cgroup() cgroups1.Cgroup {
	return v.cg
}

func (v *V1Manager) GetV2Manager() *cgroups2.Manager {
	return nil
}

// V2Manager wraps cgroup v2 operations
type V2Manager struct {
	mgr  cgroups2.Manager
	path string
}

func (v *V2Manager) Create(pid int) error {
	return v.mgr.AddProc(uint64(pid))
}

func (v *V2Manager) Stats() (*cgroups1stats.Metrics, error) {
	v2Stats, err := v.mgr.Stat()
	if err != nil {
		return nil, err
	}
	// Convert v2 stats to v1 stats format for compatibility
	return convertV2StatsToV1Stats(v2Stats), nil
}

func (v *V2Manager) Update(resources *oci.LinuxResources) error {
	v2Resources := convertToV2Resources(resources)
	return v.mgr.Update(v2Resources)
}

func (v *V2Manager) AddTask(pid int) error {
	return v.mgr.AddProc(uint64(pid))
}

func (v *V2Manager) Add(process cgroups1.Process, names ...cgroups1.Name) error {
	// Convert v1 Process to v2 process (v2 doesn't use subsystem names)
	return v.mgr.AddProc(uint64(process.Pid))
}

func (v *V2Manager) Delete() error {
	return v.mgr.Delete()
}

func (v *V2Manager) RegisterMemoryEvent(event cgroups1.MemoryEvent) (uintptr, error) {
	// Construct the full cgroup path
	fullPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(v.path, "/"))

	// Check if the cgroup path exists first
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		// Try to create the cgroup directory if it doesn't exist
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return 0, errors.Wrapf(err, "cgroup path does not exist and cannot be created: %s", v.path)
		}
		logrus.WithField("path", v.path).Info("Created missing cgroup directory")
	}

	// Create eventfd for notifications
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create eventfd for v2 memory event")
	}

	// Extract threshold from event - use method call with proper error handling
	var thresholdStr string
	defer func() {
		if r := recover(); r != nil {
			// If Arg() panics, use default threshold
			thresholdStr = ""
		}
	}()
	thresholdStr = event.Arg()

	threshold, err := strconv.ParseUint(thresholdStr, 10, 64)
	if err != nil {
		// Default to 50MB if parsing fails
		threshold = 50 * 1024 * 1024
		logrus.WithError(err).WithField("arg", thresholdStr).Warn("Failed to parse threshold from event, using default")
	}

	// Start background monitoring goroutine for cgroup v2
	go func() {
		var lastMemoryUsage uint64
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		logrus.WithFields(logrus.Fields{
			"cgroup_version": "v2",
			"path":           v.path,
			"threshold":      threshold,
		}).Info("Started cgroup v2 memory threshold monitoring")

		for range ticker.C {
			// Read current memory usage
			currentUsage, err := readMemoryCurrentV2(v.path)
			if err != nil {
				logrus.WithError(err).WithField("path", v.path).Debug("failed to read memory.current")
				continue
			}

			// Check if threshold crossed (and it's an increase)
			if currentUsage > threshold && currentUsage > lastMemoryUsage {
				// Write to eventfd to notify readMemoryEvents
				if _, err := unix.Write(fd, []byte{1, 0, 0, 0, 0, 0, 0, 0}); err != nil {
					logrus.WithError(err).Debug("failed to write to eventfd")
				} else {
					logrus.WithFields(logrus.Fields{
						"current_usage": currentUsage,
						"threshold":     threshold,
						"path":          v.path,
					}).Info("cgroup v2 memory threshold crossed, eventfd notified")
				}
			}
			lastMemoryUsage = currentUsage
		}
	}()

	logrus.WithFields(logrus.Fields{
		"cgroup_version": "v2",
		"event_type":     "memory_threshold",
		"path":           v.path,
	}).Info("Created cgroup v2 memory event monitoring (active)")
	return uintptr(fd), nil
}

func (v *V2Manager) OOMEventFD() (uintptr, error) {
	// Create eventfd for OOM notifications
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC)
	if err != nil {
		return 0, errors.Wrap(err, "failed to create eventfd for v2 OOM event")
	}

	// Start background OOM monitoring goroutine for cgroup v2
	go func() {
		var lastOOMKillCount uint64
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		logrus.WithFields(logrus.Fields{
			"cgroup_version": "v2",
			"path":           v.path,
		}).Info("Started cgroup v2 OOM monitoring")

		for range ticker.C {
			// Read memory.events file
			eventsPath := filepath.Join("/sys/fs/cgroup", v.path, "memory.events")
			data, err := os.ReadFile(eventsPath)
			if err != nil {
				logrus.WithError(err).WithField("path", v.path).Debug("failed to read memory.events")
				continue
			}

			// Parse events and check for OOM kills
			events := parseMemoryEvents(string(data))
			oomKillCount := events["oom_kill"]

			// Check if new OOM kill occurred
			if oomKillCount > lastOOMKillCount {
				// Write to eventfd to notify readMemoryEvents
				if _, err := unix.Write(fd, []byte{1, 0, 0, 0, 0, 0, 0, 0}); err != nil {
					logrus.WithError(err).Debug("failed to write to OOM eventfd")
				} else {
					logrus.WithFields(logrus.Fields{
						"oom_kill_count": oomKillCount,
						"path":           v.path,
					}).Warn("cgroup v2 OOM kill detected, eventfd notified")
				}
				lastOOMKillCount = oomKillCount
			}
		}
	}()

	logrus.WithFields(logrus.Fields{
		"cgroup_version": "v2",
		"event_type":     "oom",
		"path":           v.path,
	}).Info("Created cgroup v2 OOM event monitoring (active)")
	return uintptr(fd), nil
}

func (v *V2Manager) GetV1Cgroup() cgroups1.Cgroup {
	return nil
}

func (v *V2Manager) GetV2Manager() *cgroups2.Manager {
	return &v.mgr
}

// parseMemoryEvents parses cgroup v2 memory.events file
// Format: "low 0\nhigh 5\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"
func parseMemoryEvents(content string) map[string]uint64 {
	events := make(map[string]uint64)
	lines := strings.Split(strings.TrimSpace(content), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			if val, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				events[parts[0]] = val
			}
		}
	}
	return events
}

// readMemoryCurrentV2 reads current memory usage from cgroup v2
func readMemoryCurrentV2(cgroupPath string) (uint64, error) {
	filePath := filepath.Join("/sys/fs/cgroup", cgroupPath, "memory.current")
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}

// convertV2StatsToV1Stats converts cgroup v2 stats to v1 stats format
func convertV2StatsToV1Stats(v2Stats *cgroups2stats.Metrics) *cgroups1stats.Metrics {
	if v2Stats == nil {
		return &cgroups1stats.Metrics{}
	}

	v1Stats := &cgroups1stats.Metrics{}

	if v2Stats.Memory != nil {
		v1Stats.Memory = &cgroups1stats.MemoryStat{
			Usage: &cgroups1stats.MemoryEntry{
				Usage: v2Stats.Memory.Usage,
				Limit: v2Stats.Memory.UsageLimit,
				Max:   v2Stats.Memory.MaxUsage,
			},
			Swap: &cgroups1stats.MemoryEntry{
				Usage: v2Stats.Memory.SwapUsage,
				Limit: v2Stats.Memory.SwapLimit,
				Max:   v2Stats.Memory.SwapMaxUsage,
			},
			HierarchicalMemoryLimit: v2Stats.Memory.UsageLimit,
			HierarchicalSwapLimit:   v2Stats.Memory.SwapLimit,
			RSS:                     v2Stats.Memory.Anon,
			Cache:                   v2Stats.Memory.File,
			MappedFile:              v2Stats.Memory.FileMapped,
			Dirty:                   v2Stats.Memory.FileDirty,
			Writeback:               v2Stats.Memory.FileWriteback,
			PgFault:                 v2Stats.Memory.Pgfault,
			PgMajFault:              v2Stats.Memory.Pgmajfault,
			InactiveAnon:            v2Stats.Memory.InactiveAnon,
			ActiveAnon:              v2Stats.Memory.ActiveAnon,
			InactiveFile:            v2Stats.Memory.InactiveFile,
			ActiveFile:              v2Stats.Memory.ActiveFile,
			Unevictable:             v2Stats.Memory.Unevictable,
		}
	}

	if v2Stats.CPU != nil {
		v1Stats.CPU = &cgroups1stats.CPUStat{
			Usage: &cgroups1stats.CPUUsage{
				Total:  v2Stats.CPU.UsageUsec * 1000,  // Convert usec to nsec
				User:   v2Stats.CPU.UserUsec * 1000,   // Convert usec to nsec
				Kernel: v2Stats.CPU.SystemUsec * 1000, // Convert usec to nsec
			},
			Throttling: &cgroups1stats.Throttle{
				Periods:          v2Stats.CPU.NrPeriods,
				ThrottledPeriods: v2Stats.CPU.NrThrottled,
				ThrottledTime:    v2Stats.CPU.ThrottledUsec * 1000, // Convert usec to nsec
			},
		}
	}

	if v2Stats.Pids != nil {
		v1Stats.Pids = &cgroups1stats.PidsStat{
			Current: v2Stats.Pids.Current,
			Limit:   v2Stats.Pids.Limit,
		}
	}

	return v1Stats
}

// convertToV2Resources converts oci.LinuxResources to cgroups2.Resources
func convertToV2Resources(resources *oci.LinuxResources) *cgroups2.Resources {
	if resources == nil {
		return &cgroups2.Resources{}
	}
	v2Resources := &cgroups2.Resources{}

	// Convert memory settings
	if resources.Memory != nil {
		if resources.Memory.Limit != nil {
			v2Resources.Memory = &cgroups2.Memory{
				Max: resources.Memory.Limit,
			}
		}
	}

	// Convert CPU settings
	if resources.CPU != nil {
		v2Resources.CPU = &cgroups2.CPU{}
		if resources.CPU.Shares != nil {
			// Convert CPU shares to weight (cgroup v2 uses weight instead of shares)
			// Formula: weight = 1 + (shares - 2) * 9999 / 262142
			weight := uint64(1 + (*resources.CPU.Shares-2)*9999/262142)
			v2Resources.CPU.Weight = &weight
		}
	}

	return v2Resources
}

// createCgroupManager creates appropriate cgroup manager based on system version
func createCgroupManager(path string, resources *oci.LinuxResources) (CgroupManager, error) {
	if isCgroupV2() {
		logrus.Info("Creating cgroup v2 manager for path: " + path)
		// Create cgroup v2 manager with converted resources
		v2Resources := convertToV2Resources(resources)
		mgr, err := cgroups2.NewManager("/sys/fs/cgroup", path, v2Resources)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create cgroup v2 manager")
		}
		return &V2Manager{mgr: *mgr, path: path}, nil
	} else {
		logrus.Info("Creating cgroup v1 manager for path: " + path)
		// Create cgroup v1 manager
		cg, err := cgroups1.New(cgroups1.StaticPath(path), resources)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create cgroup v1 manager")
		}
		return &V1Manager{cg: cg}, nil
	}
}

func memoryLogFormat(metrics *cgroups1stats.Metrics) logrus.Fields {
	return logrus.Fields{
		"memoryUsage":      metrics.Memory.Usage.Usage,
		"memoryUsageMax":   metrics.Memory.Usage.Max,
		"memoryUsageLimit": metrics.Memory.Usage.Limit,
		"swapUsage":        metrics.Memory.Swap.Usage,
		"swapUsageMax":     metrics.Memory.Swap.Max,
		"swapUsageLimit":   metrics.Memory.Swap.Limit,
		"kernelUsage":      metrics.Memory.Kernel.Usage,
		"kernelUsageMax":   metrics.Memory.Kernel.Max,
		"kernelUsageLimit": metrics.Memory.Kernel.Limit,
	}
}

func readMemoryEvents(startTime time.Time, efdFile *os.File, cgName string, threshold int64, cg cgroups1.Cgroup) {
	// Buffer must be >= 8 bytes for eventfd reads
	// http://man7.org/linux/man-pages/man2/eventfd.2.html
	count := 0
	buf := make([]byte, 8)
	for {
		if _, err := efdFile.Read(buf); err != nil {
			logrus.WithError(err).WithField("cgroup", cgName).Error("failed to read from eventfd")
			return
		}

		// For cgroup v1, check if event_control file still exists (for teardown detection)
		// For cgroup v2, we skip this check since event_control doesn't exist
		if cg != nil {
			// cgroup v1 path
			_, err := os.Lstat(fmt.Sprintf("/sys/fs/cgroup/memory%s/cgroup.event_control", cgName))
			if os.IsNotExist(err) {
				return
			}
		}

		count++
		var msg string
		if strings.HasPrefix(cgName, "/virtual-pods") {
			msg = "memory usage for virtual pods cgroup exceeded threshold"
		} else if strings.Contains(cgName, "oom") || strings.Contains(cgName, "OOM") {
			msg = "OOM event occurred in cgroup"
		} else {
			msg = "memory usage for cgroup exceeded threshold"
		}

		entry := logrus.WithFields(logrus.Fields{
			"gcsStartTime":   startTime,
			"time":           time.Now(),
			"cgroup":         cgName,
			"thresholdBytes": threshold,
			"count":          count,
			"cgroup_version": func() string {
				if cg != nil {
					return "v1"
				} else {
					return "v2"
				}
			}(),
		})

		// Sleep for one second in case there is a series of allocations slightly after
		// reaching threshold.
		time.Sleep(time.Second)

		if cg != nil {
			// cgroup v1: get detailed stats
			metrics, err := cg.Stat(cgroups1.IgnoreNotExist)
			if err != nil {
				// Don't return on Stat err as it will return an error if
				// any of the cgroup subsystems Stat calls failed for any reason.
				// We still want to log if we hit the cgroup threshold/limit
				entry.WithError(err).Error(msg)
			} else {
				entry.WithFields(memoryLogFormat(metrics)).Warn(msg)
			}
		} else {
			// cgroup v2: simpler logging without detailed metrics
			entry.Warn(msg)
		}
	}
}

// runWithRestartMonitor starts a command with given args and waits for it to exit. If the
// command exit code is non-zero the command is restarted with with some back off delay.
// Any stdout or stderr of the command will be split into lines and written as a log with
// logrus standard logger.  This function must be called in a separate goroutine.
func runWithRestartMonitor(arg0 string, args ...string) {
	backoffSettings := backoff.NewExponentialBackOff()
	// After we hit 10 min retry interval keep retrying after every 10 mins instead of
	// continuing to increase retry interval.
	backoffSettings.MaxInterval = time.Minute * 10
	for {
		command := exec.Command(arg0, args...)
		if err := command.Run(); err != nil {
			logrus.WithFields(logrus.Fields{
				"error":   err,
				"command": command.Args,
			}).Warn("restart monitor: run command returns error")
		}
		backOffTime := backoffSettings.NextBackOff()
		// since backoffSettings.MaxElapsedTime is set to 0 we will never receive backoff.Stop.
		time.Sleep(backOffTime)
	}
}

// startTimeSyncService starts the `chronyd` deamon to keep the UVM time synchronized.  We
// use a PTP device provided by the hypervisor as a source of correct time (instead of
// using a network server). We need to create a configuration file that configures chronyd
// to use the PTP device.  The system can have multiple PTP devices so we identify the
// correct PTP device by verifying that the `clock_name` of that device is `hyperv`.
func startTimeSyncService() error {
	ptpClassDir, err := os.Open("/sys/class/ptp")
	if err != nil {
		return errors.Wrap(err, "failed to open PTP class directory")
	}

	ptpDirList, err := ptpClassDir.Readdirnames(-1)
	if err != nil {
		return errors.Wrap(err, "failed to list PTP class directory")
	}

	var ptpDirPath string
	found := false
	// The file ends with a new line
	expectedClockName := "hyperv\n"
	for _, ptpDirPath = range ptpDirList {
		clockNameFilePath := filepath.Join(ptpClassDir.Name(), ptpDirPath, "clock_name")
		buf, err := os.ReadFile(clockNameFilePath)
		if err != nil && !os.IsNotExist(err) {
			return errors.Wrapf(err, "failed to read clock name file at %s", clockNameFilePath)
		}

		if string(buf) == expectedClockName {
			found = true
			break
		}
	}

	if !found {
		return errors.Errorf("no PTP device found with name \"%s\"", expectedClockName)
	}

	// create chronyd config file
	ptpDevPath := filepath.Join("/dev", filepath.Base(ptpDirPath))
	// chronyd config file take from: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/time-sync
	chronydConfigString := fmt.Sprintf("refclock PHC %s poll 3 dpoll -2 offset 0 stratum 2\nmakestep 0.1 -1\n", ptpDevPath)
	chronydConfPath := "/tmp/chronyd.conf"
	err = os.WriteFile(chronydConfPath, []byte(chronydConfigString), 0644)
	if err != nil {
		return errors.Wrapf(err, "failed to create chronyd conf file %s", chronydConfPath)
	}

	// start chronyd. Do NOT start chronyd as daemon because creating a daemon
	// involves double forking the restart monitor will attempt to restart chornyd
	// after the first fork child exits.
	go runWithRestartMonitor("chronyd", "-n", "-f", chronydConfPath)
	return nil
}

func main() {
	startTime := time.Now()
	logLevel := flag.String("loglevel",
		"debug",
		"Logging Level: debug, info, warning, error, fatal, panic.")
	coreDumpLoc := flag.String("core-dump-location",
		"",
		"The location/format where process core dumps will be written to.")
	kmsgLogLevel := flag.Uint("kmsgLogLevel",
		uint(kmsg.Warning),
		"Log all kmsg entries with a priority less than or equal to the supplied level.")
	logFile := flag.String("logfile",
		"",
		"Logging Target: An optional file name/path. Omit for console output.")
	logFormat := flag.String("log-format", "text", "Logging Format: text or json")
	useInOutErr := flag.Bool("use-inouterr",
		false,
		"If true use stdin/stdout for bridge communication and stderr for logging")
	v4 := flag.Bool("v4", false, "enable the v4 protocol support and v2 schema")
	rootMemReserveBytes := flag.Uint64("root-mem-reserve-bytes",
		75*1024*1024, // 75Mib
		"the amount of memory reserved for the orchestration, the rest will be assigned to containers")
	gcsMemLimitBytes := flag.Uint64("gcs-mem-limit-bytes",
		50*1024*1024, // 50 MiB
		"the maximum amount of memory the gcs can use")
	disableTimeSync := flag.Bool("disable-time-sync",
		false,
		"If true do not run chronyd time synchronization service inside the UVM")
	scrubLogs := flag.Bool("scrub-logs", false, "If true, scrub potentially sensitive information from logging")
	initialPolicyStance := flag.String("initial-policy-stance",
		"allow",
		"Stance: allow, deny.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "    %s -loglevel=debug -logfile=/run/gcs/gcs.log\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "    %s -loglevel=info -logfile=stdout\n", os.Args[0])
	}

	flag.Parse()

	// If v4 enable opencensus
	if *v4 {
		trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
		trace.RegisterExporter(&oc.LogrusExporter{})
	}

	logrus.AddHook(log.NewHook())

	var logWriter *os.File
	if *logFile != "" {
		logFileHandle, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"path":          *logFile,
				logrus.ErrorKey: err,
			}).Fatal("failed to create log file")
		}
		logWriter = logFileHandle
	} else {
		// logrus uses os.Stderr. see logrus.New()
		logWriter = os.Stderr
	}

	// set up our initial stance policy enforcer
	var initialEnforcer securitypolicy.SecurityPolicyEnforcer
	switch *initialPolicyStance {
	case "allow":
		initialEnforcer = &securitypolicy.OpenDoorSecurityPolicyEnforcer{}
		logrus.SetOutput(logWriter)
	case "deny":
		initialEnforcer = &securitypolicy.ClosedDoorSecurityPolicyEnforcer{}
		logrus.SetOutput(io.Discard)
	default:
		logrus.WithFields(logrus.Fields{
			"initial-policy-stance": *initialPolicyStance,
		}).Fatal("unknown initial-policy-stance")
	}

	switch *logFormat {
	case "text":
		// retain logrus's default.
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano, // include ns for accurate comparisons on the host
		})
	default:
		logrus.WithFields(logrus.Fields{
			"log-format": *logFormat,
		}).Fatal("unknown log-format")
	}

	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.SetLevel(level)

	log.SetScrubbing(*scrubLogs)

	baseLogPath := guestpath.LCOWRootPrefixInUVM

	logrus.WithFields(logrus.Fields{
		"branch":  version.Branch,
		"commit":  version.Commit,
		"version": version.Version,
	}).Info("GCS started")

	// Log which cgroup version is detected and will be used
	if isCgroupV2() {
		logrus.Info("cgroup v2 detected by GCS - using v2 API")
	} else {
		logrus.Info("cgroup v1 detected by GCS - using v1 API")
	}

	// Set the process core dump location. This will be global to all containers as it's a kernel configuration.
	// If no path is specified core dumps will just be placed in the working directory of wherever the process
	// was invoked to a file named "core".
	if *coreDumpLoc != "" {
		if err := os.WriteFile(
			"/proc/sys/kernel/core_pattern",
			[]byte(*coreDumpLoc),
			0644,
		); err != nil {
			logrus.WithError(err).Fatal("failed to set core dump location")
		}
	}

	// Continuously log /dev/kmsg
	go kmsg.ReadForever(kmsg.LogLevel(*kmsgLogLevel))

	// Setup the UVM cgroups to protect against a workload taking all available
	// memory and causing the GCS to malfunction we create cgroups: gcs,
	// containers, and virtual-pods for multi-pod support.
	//

	// Write 1 to memory.use_hierarchy on the root cgroup to enable hierarchy
	// support. This needs to be set before we create any cgroups as the write
	// will fail otherwise. This is only needed for cgroup v1.
	if !isCgroupV2() {
		if err := os.WriteFile("/sys/fs/cgroup/memory/memory.use_hierarchy", []byte("1"), 0644); err != nil {
			logrus.WithError(err).Fatal("failed to enable hierarchy support for root cgroup")
		}
	} else {
		logrus.Info("cgroup v2 detected - hierarchy always enabled, skipping memory.use_hierarchy")
	}

	// The containers cgroup is limited only by {Totalram - 75 MB
	// (reservation)}.
	//
	// The gcs cgroup is not limited but an event will get logged if memory
	// usage exceeds 50 MB.
	sinfo := syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(&sinfo); err != nil {
		logrus.WithError(err).Fatal("failed to get sys info")
	}
	containersLimit := int64(sinfo.Totalram - *rootMemReserveBytes)
	containersControl, err := createCgroupManager("/containers", &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &containersLimit,
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to create containers cgroup")
	}
	defer containersControl.Delete() //nolint:errcheck

	// Create virtual-pods cgroup hierarchy for multi-pod support
	// This will be the parent for all virtual pod cgroups: /containers/virtual-pods/{virtualSandboxID}
	virtualPodsControl, err := createCgroupManager("/containers/virtual-pods", &oci.LinuxResources{
		Memory: &oci.LinuxMemory{
			Limit: &containersLimit, // Share the same limit as containers
		},
	})
	if err != nil {
		logrus.WithError(err).Fatal("failed to create containers/virtual-pods cgroup")
	}
	defer virtualPodsControl.Delete() //nolint:errcheck

	gcsControl, err := createCgroupManager("/gcs", &oci.LinuxResources{})
	if err != nil {
		logrus.WithError(err).Fatal("failed to create gcs cgroup")
	}
	defer gcsControl.Delete() //nolint:errcheck
	if err := gcsControl.Add(cgroups1.Process{Pid: os.Getpid()}); err != nil {
		logrus.WithError(err).Fatal("failed add gcs pid to gcs cgroup")
	}

	tport := &transport.VsockTransport{}
	rtime, err := runc.NewRuntime(baseLogPath)
	if err != nil {
		logrus.WithError(err).Fatal("failed to initialize new runc runtime")
	}
	mux := bridge.NewBridgeMux()
	b := bridge.Bridge{
		Handler:  mux,
		EnableV4: *v4,
	}
	h := hcsv2.NewHost(rtime, tport, initialEnforcer, logWriter)
	// Initialize virtual pod support in the host
	if err := h.InitializeVirtualPodSupport(virtualPodsControl); err != nil {
		logrus.WithError(err).Warn("Virtual pod support initialization failed")
	}
	b.AssignHandlers(mux, h)

	var bridgeIn io.ReadCloser
	var bridgeOut io.WriteCloser
	if *useInOutErr {
		bridgeIn = os.Stdin
		bridgeOut = os.Stdout
	} else {
		const commandPort uint32 = 0x40000000
		bridgeCon, err := tport.Dial(commandPort)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"port":          commandPort,
				logrus.ErrorKey: err,
			}).Fatal("failed to dial host vsock connection")
		}
		bridgeIn = bridgeCon
		bridgeOut = bridgeCon
	}

	event := cgroups1.MemoryThresholdEvent(*gcsMemLimitBytes, false)
	gefd, err := gcsControl.RegisterMemoryEvent(event)
	if err != nil {
		logrus.WithError(err).Fatal("failed to register memory threshold for gcs cgroup")
	}
	gefdFile := os.NewFile(gefd, "gefd")
	defer gefdFile.Close()

	oom, err := containersControl.OOMEventFD()
	if err != nil {
		logrus.WithError(err).Fatal("failed to retrieve the container cgroups oom eventfd")
	}
	oomFile := os.NewFile(oom, "cefd")
	defer oomFile.Close()

	// Setup OOM monitoring for virtual-pods cgroup
	virtualPodsOom, err := virtualPodsControl.OOMEventFD()
	if err != nil {
		logrus.WithError(err).Fatal("failed to retrieve the virtual-pods cgroups oom eventfd")
	}
	virtualPodsOomFile := os.NewFile(virtualPodsOom, "vp-oomfd")
	defer virtualPodsOomFile.Close()

	// time synchronization service
	if !(*disableTimeSync) {
		if err = startTimeSyncService(); err != nil {
			logrus.WithError(err).Fatal("failed to start time synchronization service")
		}
	}

	go func() {
		if v1Cgroup := gcsControl.GetV1Cgroup(); v1Cgroup != nil {
			// cgroup v1: use existing readMemoryEvents function
			readMemoryEvents(startTime, gefdFile, "/gcs", int64(*gcsMemLimitBytes), v1Cgroup)
		} else {
			// cgroup v2: use same readMemoryEvents but with polling-based eventfd
			logrus.Info("Memory events for /gcs enabled for cgroup v2 with polling")
			// Create a dummy cgroup for the readMemoryEvents function (it won't be used for v2)
			readMemoryEvents(startTime, gefdFile, "/gcs", int64(*gcsMemLimitBytes), nil)
		}
	}()
	go func() {
		if v1Cgroup := containersControl.GetV1Cgroup(); v1Cgroup != nil {
			// cgroup v1: use existing readMemoryEvents function
			readMemoryEvents(startTime, oomFile, "/containers", containersLimit, v1Cgroup)
		} else {
			// cgroup v2: use same readMemoryEvents but with polling-based eventfd
			logrus.Info("Memory events for /containers enabled for cgroup v2 with polling")
			readMemoryEvents(startTime, oomFile, "/containers", containersLimit, nil)
		}
	}()
	go func() {
		if v1Cgroup := virtualPodsControl.GetV1Cgroup(); v1Cgroup != nil {
			// cgroup v1: use existing readMemoryEvents function
			readMemoryEvents(startTime, virtualPodsOomFile, "/containers/virtual-pods", containersLimit, v1Cgroup)
		} else {
			// cgroup v2: use same readMemoryEvents but with polling-based eventfd
			logrus.Info("Memory events for /containers/virtual-pods enabled for cgroup v2 with polling")
			readMemoryEvents(startTime, virtualPodsOomFile, "/containers/virtual-pods", containersLimit, nil)
		}
	}()
	err = b.ListenAndServe(bridgeIn, bridgeOut)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			logrus.ErrorKey: err,
		}).Fatal("failed to serve gcs service")
	}
}
