//go:build linux
// +build linux

package hcsv2

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	cgroups "github.com/containerd/cgroups/v3/cgroup1"
	v1 "github.com/containerd/cgroups/v3/cgroup1/stats"
	cgroups2 "github.com/containerd/cgroups/v3/cgroup2"
	v2 "github.com/containerd/cgroups/v3/cgroup2/stats"
	oci "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.opencensus.io/trace"

	"github.com/Microsoft/hcsshim/internal/bridgeutils/gcserr"
	"github.com/Microsoft/hcsshim/internal/guest/prot"
	"github.com/Microsoft/hcsshim/internal/guest/runtime"
	specGuest "github.com/Microsoft/hcsshim/internal/guest/spec"
	"github.com/Microsoft/hcsshim/internal/guest/stdio"
	"github.com/Microsoft/hcsshim/internal/guest/storage"
	"github.com/Microsoft/hcsshim/internal/guest/transport"
	"github.com/Microsoft/hcsshim/internal/log"
	"github.com/Microsoft/hcsshim/internal/logfields"
	"github.com/Microsoft/hcsshim/internal/oc"
	"github.com/Microsoft/hcsshim/internal/protocol/guestrequest"
	"github.com/Microsoft/hcsshim/internal/protocol/guestresource"
	"github.com/Microsoft/hcsshim/pkg/annotations"
)

// containerStatus has been introduced to enable parallel container creation
type containerStatus uint32

const (
	// containerCreating is the default status set on a Container object, when
	// no underlying runtime container or init process has been assigned
	containerCreating containerStatus = iota
	// containerCreated is the status when a runtime container and init process
	// have been assigned, but runtime start command has not been issued yet
	containerCreated
)

type Container struct {
	id string

	vsock   transport.Transport
	logPath string   // path to [logFile].
	logFile *os.File // file to redirect container's stdio to.

	spec          *oci.Spec
	ociBundlePath string
	isSandbox     bool

	container   runtime.Container
	initProcess *containerProcess

	etL      sync.Mutex
	exitType prot.NotificationType

	processesMutex sync.Mutex
	processes      map[uint32]*containerProcess

	// current container (creation) status.
	// Only access through [getStatus] and [setStatus].
	//
	// Note: its more ergonomic to store the uint32 and convert to/from [containerStatus]
	// then use [atomic.Value] and deal with unsafe conversions to/from [any], or use [atomic.Pointer]
	// and deal with the extra pointer dereferencing overhead.
	status atomic.Uint32

	// scratchDirPath represents the path inside the UVM where the scratch directory
	// of this container is located. Usually, this is either `/run/gcs/c/<containerID>` or
	// `/run/gcs/c/<UVMID>/container_<containerID>` if scratch is shared with UVM scratch.
	scratchDirPath string
}

func (c *Container) Start(ctx context.Context, conSettings stdio.ConnectionSettings) (_ int, err error) {
	entity := log.G(ctx).WithField(logfields.ContainerID, c.id)
	entity.Info("opengcs::Container::Start")

	// only use the logfile for the init process, since we don't want to tee stdio of execs
	t := c.vsock
	if c.logPath != "" {
		// don't use [os.Create] since that truncates an existing file, which is not desired
		if c.logFile, err = os.OpenFile(c.logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
			return -1, fmt.Errorf("failed to open log file: %s: %w", c.logPath, err)
		}
		go func() {
			// initProcess is already created in [(*Host).CreateContainer], and is, therefore, "waitable"
			// wait in `writersWg`, which is closed after process is cleaned up (including io Relays)
			//
			// Note: [PipeRelay] and [TtyRelay] are not safe to call multiple times, so it is safer to wait
			// on the parent (init) process.
			c.initProcess.writersWg.Wait()

			if lfErr := c.logFile.Close(); lfErr != nil {
				entity.WithFields(logrus.Fields{
					logrus.ErrorKey: lfErr,
					logfields.Path:  c.logFile.Name(),
				}).Warn("failed to close log file")
			}
			c.logFile = nil
		}()

		t = transport.NewMultiWriter(c.vsock, c.logFile)
	}

	stdioSet, err := stdio.Connect(t, conSettings)
	if err != nil {
		return -1, err
	}

	if c.initProcess.spec.Terminal {
		ttyr := c.container.Tty()
		ttyr.ReplaceConnectionSet(stdioSet)
		ttyr.Start()
	} else {
		pr := c.container.PipeRelay()
		pr.ReplaceConnectionSet(stdioSet)
		pr.CloseUnusedPipes()
		pr.Start()
	}
	err = c.container.Start()
	if err != nil {
		stdioSet.Close()
	}
	return int(c.initProcess.pid), err
}

func (c *Container) ExecProcess(ctx context.Context, process *oci.Process, conSettings stdio.ConnectionSettings) (int, error) {
	log.G(ctx).WithField(logfields.ContainerID, c.id).Info("opengcs::Container::ExecProcess")
	stdioSet, err := stdio.Connect(c.vsock, conSettings)
	if err != nil {
		return -1, err
	}

	// Add in the core rlimit specified on the container in case there was one set. This makes it so that execed processes can also generate
	// core dumps.
	process.Rlimits = c.spec.Process.Rlimits

	// If the client provided a user for the container to run as, we want to have the exec run as this user as well
	// unless the exec's spec was explicitly set to a different user. If the Username field is filled in on the containers
	// spec, at this point that means the work to find a uid:gid pairing for this username has already been done, so simply
	// assign the uid:gid from the container.
	if process.User.Username != "" {
		// The exec provided a user string of it's own. Grab the uid:gid pairing for the string (if one exists).
		if err := specGuest.SetUserStr(&oci.Spec{Root: c.spec.Root, Process: process}, process.User.Username); err != nil {
			return -1, err
		}
		// Runc doesn't care about this, and just to be safe clear it.
		process.User.Username = ""
	} else if c.spec.Process.User.Username != "" {
		process.User = c.spec.Process.User
	}

	p, err := c.container.ExecProcess(process, stdioSet)
	if err != nil {
		stdioSet.Close()
		return -1, err
	}

	pid := p.Pid()
	c.processesMutex.Lock()
	c.processes[uint32(pid)] = newProcess(c, process, p, uint32(pid), false)
	c.processesMutex.Unlock()
	return pid, nil
}

// InitProcess returns the container's init process
func (c *Container) InitProcess() Process {
	return c.initProcess
}

// GetProcess returns the Process with the matching 'pid'. If the 'pid' does
// not exit returns error.
func (c *Container) GetProcess(pid uint32) (Process, error) {
	//todo: thread a context to this function call
	logrus.WithFields(logrus.Fields{
		logfields.ContainerID: c.id,
		logfields.ProcessID:   pid,
	}).Info("opengcs::Container::GetProcess")
	if c.initProcess.pid == pid {
		return c.initProcess, nil
	}

	c.processesMutex.Lock()
	defer c.processesMutex.Unlock()

	p, ok := c.processes[pid]
	if !ok {
		return nil, gcserr.NewHresultError(gcserr.HrErrNotFound)
	}
	return p, nil
}

// GetAllProcessPids returns all process pids in the container namespace.
func (c *Container) GetAllProcessPids(ctx context.Context) ([]int, error) {
	log.G(ctx).WithField(logfields.ContainerID, c.id).Info("opengcs::Container::GetAllProcessPids")
	state, err := c.container.GetAllProcesses()
	if err != nil {
		return nil, err
	}
	pids := make([]int, len(state))
	for i, s := range state {
		pids[i] = s.Pid
	}
	return pids, nil
}

// Kill sends 'signal' to the container process.
func (c *Container) Kill(ctx context.Context, signal syscall.Signal) error {
	log.G(ctx).WithFields(logrus.Fields{
		logfields.ContainerID: c.id,
		"signal":              signal.String(),
	}).Info("opengcs::Container::Kill")
	err := c.container.Kill(signal)
	if err != nil {
		return err
	}
	c.setExitType(signal)
	return nil
}

func (c *Container) Delete(ctx context.Context) error {
	entity := log.G(ctx).WithField(logfields.ContainerID, c.id)
	entity.Info("opengcs::Container::Delete")
	if c.isSandbox {
		// Check if this is a virtual pod
		virtualSandboxID := ""
		if c.spec != nil && c.spec.Annotations != nil {
			virtualSandboxID = c.spec.Annotations[annotations.VirtualPodID]
		}

		// remove user mounts in sandbox container - use virtual pod aware paths
		if err := storage.UnmountAllInPath(ctx, specGuest.VirtualPodAwareSandboxMountsDir(c.id, virtualSandboxID), true); err != nil {
			entity.WithError(err).Error("failed to unmount sandbox mounts")
		}

		// remove user mounts in tmpfs sandbox container - use virtual pod aware paths
		if err := storage.UnmountAllInPath(ctx, specGuest.VirtualPodAwareSandboxTmpfsMountsDir(c.id, virtualSandboxID), true); err != nil {
			entity.WithError(err).Error("failed to unmount tmpfs sandbox mounts")
		}

		// remove hugepages mounts in sandbox container - use virtual pod aware paths
		if err := storage.UnmountAllInPath(ctx, specGuest.VirtualPodAwareHugePagesMountsDir(c.id, virtualSandboxID), true); err != nil {
			entity.WithError(err).Error("failed to unmount hugepages mounts")
		}
	}

	var retErr error
	if err := c.container.Delete(); err != nil {
		retErr = err
	}

	if err := os.RemoveAll(c.scratchDirPath); err != nil {
		if retErr != nil {
			retErr = fmt.Errorf("errors deleting container state: %w; %w", retErr, err)
		} else {
			retErr = err
		}
	}

	if err := os.RemoveAll(c.ociBundlePath); err != nil {
		if retErr != nil {
			retErr = fmt.Errorf("errors deleting container oci bundle dir: %w; %w", retErr, err)
		} else {
			retErr = err
		}
	}

	return retErr
}

func (c *Container) Update(ctx context.Context, resources interface{}) error {
	log.G(ctx).WithField(logfields.ContainerID, c.id).Info("opengcs::Container::Update")
	return c.container.Update(resources)
}

// Wait waits for the container's init process to exit.
func (c *Container) Wait() prot.NotificationType {
	_, span := oc.StartSpan(context.Background(), "opengcs::Container::Wait")
	defer span.End()
	span.AddAttributes(trace.StringAttribute(logfields.ContainerID, c.id))

	c.initProcess.writersWg.Wait()
	c.etL.Lock()
	defer c.etL.Unlock()
	return c.exitType
}

// setExitType sets `c.exitType` to the appropriate value based on `signal` if
// `signal` will take down the container.
func (c *Container) setExitType(signal syscall.Signal) {
	c.etL.Lock()
	defer c.etL.Unlock()

	switch signal {
	case syscall.SIGTERM:
		c.exitType = prot.NtGracefulExit
	case syscall.SIGKILL:
		c.exitType = prot.NtForcedExit
	}
}

// isCgroupV2 checks if cgroup v2 is available on the system
func isCgroupV2() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// convertV2StatsToV1 converts cgroup v2 metrics to v1 metrics format
func convertV2StatsToV1(v2Stats *v2.Metrics) *v1.Metrics {
	metrics := &v1.Metrics{}

	// Convert Memory stats
	if v2Stats.Memory != nil {
		metrics.Memory = &v1.MemoryStat{
			Usage: &v1.MemoryEntry{
				Usage: v2Stats.Memory.Usage,
				Limit: v2Stats.Memory.UsageLimit,
				Max:   v2Stats.Memory.MaxUsage,
			},
			Swap: &v1.MemoryEntry{
				Usage: v2Stats.Memory.SwapUsage,
				Limit: v2Stats.Memory.SwapLimit,
				Max:   v2Stats.Memory.SwapMaxUsage,
			},
			Kernel: &v1.MemoryEntry{
				Usage: v2Stats.Memory.KernelStack, // Best approximation
				Limit: 0,                          // v2 doesn't separate kernel limits
				Max:   0,
			},
			KernelTCP: &v1.MemoryEntry{
				Usage: v2Stats.Memory.Sock, // Best approximation
				Limit: 0,
				Max:   0,
			},
			// Map some v2 fields to v1 equivalents
			Cache:        v2Stats.Memory.File,
			RSS:          v2Stats.Memory.Anon,
			MappedFile:   v2Stats.Memory.FileMapped,
			Dirty:        v2Stats.Memory.FileDirty,
			Writeback:    v2Stats.Memory.FileWriteback,
			InactiveAnon: v2Stats.Memory.InactiveAnon,
			ActiveAnon:   v2Stats.Memory.ActiveAnon,
			InactiveFile: v2Stats.Memory.InactiveFile,
			ActiveFile:   v2Stats.Memory.ActiveFile,
			Unevictable:  v2Stats.Memory.Unevictable,
		}
	}

	// Convert memory events to OOM control info in the main Metrics struct
	if v2Stats.MemoryEvents != nil {
		metrics.MemoryOomControl = &v1.MemoryOomControl{
			OomKill:        v2Stats.MemoryEvents.Oom,
			OomKillDisable: 0, // v2 doesn't have disable flag
			UnderOom:       0, // v2 doesn't track this directly
		}
	}

	// Convert CPU stats
	if v2Stats.CPU != nil {
		metrics.CPU = &v1.CPUStat{
			Usage: &v1.CPUUsage{
				Total:  v2Stats.CPU.UsageUsec * 1000, // convert usec to nsec
				Kernel: v2Stats.CPU.SystemUsec * 1000,
				User:   v2Stats.CPU.UserUsec * 1000,
			},
			Throttling: &v1.Throttle{
				Periods:          v2Stats.CPU.NrPeriods,
				ThrottledPeriods: v2Stats.CPU.NrThrottled,
				ThrottledTime:    v2Stats.CPU.ThrottledUsec * 1000,
			},
		}
	}

	// Convert IO stats (v2 Io -> v1 Blkio)
	if v2Stats.Io != nil && len(v2Stats.Io.Usage) > 0 {
		metrics.Blkio = &v1.BlkIOStat{
			IoServiceBytesRecursive: make([]*v1.BlkIOEntry, 0, len(v2Stats.Io.Usage)*2),
			IoServicedRecursive:     make([]*v1.BlkIOEntry, 0, len(v2Stats.Io.Usage)*2),
		}

		for _, entry := range v2Stats.Io.Usage {
			// Read bytes
			metrics.Blkio.IoServiceBytesRecursive = append(
				metrics.Blkio.IoServiceBytesRecursive,
				&v1.BlkIOEntry{
					Major: entry.Major,
					Minor: entry.Minor,
					Op:    "Read",
					Value: entry.Rbytes,
				},
			)
			// Write bytes
			metrics.Blkio.IoServiceBytesRecursive = append(
				metrics.Blkio.IoServiceBytesRecursive,
				&v1.BlkIOEntry{
					Major: entry.Major,
					Minor: entry.Minor,
					Op:    "Write",
					Value: entry.Wbytes,
				},
			)
			// Read IOs
			metrics.Blkio.IoServicedRecursive = append(
				metrics.Blkio.IoServicedRecursive,
				&v1.BlkIOEntry{
					Major: entry.Major,
					Minor: entry.Minor,
					Op:    "Read",
					Value: entry.Rios,
				},
			)
			// Write IOs
			metrics.Blkio.IoServicedRecursive = append(
				metrics.Blkio.IoServicedRecursive,
				&v1.BlkIOEntry{
					Major: entry.Major,
					Minor: entry.Minor,
					Op:    "Write",
					Value: entry.Wios,
				},
			)
		}
	}

	// Convert PIDs stats
	if v2Stats.Pids != nil {
		metrics.Pids = &v1.PidsStat{
			Current: v2Stats.Pids.Current,
			Limit:   v2Stats.Pids.Limit,
		}
	}

	// Convert Hugetlb stats
	if len(v2Stats.Hugetlb) > 0 {
		metrics.Hugetlb = make([]*v1.HugetlbStat, len(v2Stats.Hugetlb))
		for i, stats := range v2Stats.Hugetlb {
			metrics.Hugetlb[i] = &v1.HugetlbStat{
				Usage:   stats.Current,
				Max:     stats.Max,
				Failcnt: 0, // v2 doesn't track failure count
			}
		}
	}

	// Convert RDMA stats - both v1 and v2 use []*RdmaEntry format
	if v2Stats.Rdma != nil {
		// Need to convert v2 RdmaEntry to v1 RdmaEntry
		metrics.Rdma = &v1.RdmaStat{}

		// Convert Current entries
		if len(v2Stats.Rdma.Current) > 0 {
			metrics.Rdma.Current = make([]*v1.RdmaEntry, len(v2Stats.Rdma.Current))
			for i, entry := range v2Stats.Rdma.Current {
				metrics.Rdma.Current[i] = &v1.RdmaEntry{
					Device:     entry.Device,
					HcaHandles: entry.HcaHandles,
					HcaObjects: entry.HcaObjects,
				}
			}
		}

		// Convert Limit entries
		if len(v2Stats.Rdma.Limit) > 0 {
			metrics.Rdma.Limit = make([]*v1.RdmaEntry, len(v2Stats.Rdma.Limit))
			for i, entry := range v2Stats.Rdma.Limit {
				metrics.Rdma.Limit[i] = &v1.RdmaEntry{
					Device:     entry.Device,
					HcaHandles: entry.HcaHandles,
					HcaObjects: entry.HcaObjects,
				}
			}
		}
	}

	// Convert Network stats (v2 returns array, v1 expects array)
	if len(v2Stats.Network) > 0 {
		metrics.Network = make([]*v1.NetworkStat, len(v2Stats.Network))
		for i, netStat := range v2Stats.Network {
			metrics.Network[i] = &v1.NetworkStat{
				Name:      netStat.Name,
				RxBytes:   netStat.RxBytes,
				RxPackets: netStat.RxPackets,
				RxErrors:  netStat.RxErrors,
				RxDropped: netStat.RxDropped,
				TxBytes:   netStat.TxBytes,
				TxPackets: netStat.TxPackets,
				TxErrors:  netStat.TxErrors,
				TxDropped: netStat.TxDropped,
			}
		}
	}

	return metrics
}

// GetStats returns the cgroup metrics for the container.
// Works with both cgroup v1 and v2 systems.
func (c *Container) GetStats(ctx context.Context) (*v1.Metrics, error) {
	_, span := oc.StartSpan(ctx, "opengcs::Container::GetStats")
	defer span.End()
	span.AddAttributes(trace.StringAttribute("cid", c.id))

	cgroupPath := c.spec.Linux.CgroupsPath

	// Detect cgroup version and use appropriate library
	if isCgroupV2() {
		// Use cgroup v2 library and convert to v1.Metrics
		mgr, err := cgroups2.Load(cgroupPath)
		if err != nil {
			return nil, errors.Errorf("failed to load v2 cgroup for container %v: %v", c.id, err)
		}
		v2Stats, err := mgr.Stat()
		if err != nil {
			return nil, errors.Errorf("failed to get v2 stats for container %v: %v", c.id, err)
		}

		// Convert v2.Metrics to v1.Metrics
		return convertV2StatsToV1(v2Stats), nil
	} else {
		// Use existing v1 approach
		cg, err := cgroups.Load(cgroups.StaticPath(cgroupPath))
		if err != nil {
			return nil, errors.Errorf("failed to get container stats for %v: %v", c.id, err)
		}
		return cg.Stat(cgroups.IgnoreNotExist)
	}
}

func (c *Container) modifyContainerConstraints(ctx context.Context, _ guestrequest.RequestType, cc *guestresource.LCOWContainerConstraints) (err error) {
	return c.Update(ctx, cc.Linux)
}

func (c *Container) getStatus() containerStatus {
	return containerStatus(c.status.Load())
}

func (c *Container) setStatus(st containerStatus) {
	c.status.Store(uint32(st))
}

func (c *Container) ID() string {
	return c.id
}
