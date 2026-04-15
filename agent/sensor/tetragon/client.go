package tetragon

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/IgorEulalio/philip/agent/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	tetragonAPI "github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	defaultSocketPath = "unix:///var/run/tetragon/tetragon.sock"
	eventChanSize     = 10000
)

// Config holds Tetragon consumer configuration.
type Config struct {
	// ServerAddress is the Tetragon gRPC address (default: unix socket).
	ServerAddress string
}

// Consumer implements the sensor.Sensor interface using Tetragon's gRPC event stream.
type Consumer struct {
	cfg    Config
	conn   *grpc.ClientConn
	events chan sensor.Event
	stopCh chan struct{}
	mu     sync.Mutex
}

// New creates a new Tetragon consumer.
func New(cfg Config) *Consumer {
	if cfg.ServerAddress == "" {
		cfg.ServerAddress = defaultSocketPath
	}
	return &Consumer{
		cfg:    cfg,
		events: make(chan sensor.Event, eventChanSize),
		stopCh: make(chan struct{}),
	}
}

func (c *Consumer) Name() string {
	return "tetragon"
}

func (c *Consumer) Events() <-chan sensor.Event {
	return c.events
}

// Start connects to Tetragon and begins streaming events.
func (c *Consumer) Start(ctx context.Context) error {
	conn, err := grpc.NewClient(
		c.cfg.ServerAddress,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to connect to tetragon: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	client := tetragonAPI.NewFineGuidanceSensorsClient(conn)

	// Subscribe to the event stream
	stream, err := client.GetEvents(ctx, &tetragonAPI.GetEventsRequest{
		AllowList: []*tetragonAPI.Filter{},
	})
	if err != nil {
		return fmt.Errorf("failed to start event stream: %w", err)
	}

	for {
		select {
		case <-c.stopCh:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		res, err := stream.Recv()
		if err != nil {
			if err == io.EOF || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("event stream error: %w", err)
		}

		events := c.translateEvent(res)
		for _, evt := range events {
			select {
			case c.events <- evt:
			default:
				// Channel full — drop event (backpressure)
			}
		}
	}
}

// Stop gracefully shuts down the Tetragon consumer.
func (c *Consumer) Stop() error {
	close(c.stopCh)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// translateEvent converts a Tetragon GetEventsResponse into Philip sensor events.
func (c *Consumer) translateEvent(res *tetragonAPI.GetEventsResponse) []sensor.Event {
	var events []sensor.Event

	switch ev := res.Event.(type) {
	case *tetragonAPI.GetEventsResponse_ProcessExec:
		if ev.ProcessExec == nil || ev.ProcessExec.Process == nil {
			return nil
		}
		proc := ev.ProcessExec.Process
		events = append(events, sensor.Event{
			ID:        generateEventID(),
			Timestamp: startTimeFromProcess(proc),
			Type:      sensor.EventTypeProcessExec,
			PID:       pidFromProcess(proc),
			ParentPID: pidFromProcess(ev.ProcessExec.Parent),
			Binary:    proc.Binary,
			Args:      splitArgs(proc.Arguments),
			CWD:       proc.Cwd,
			UID:       uidFromProcess(proc),
		})

	case *tetragonAPI.GetEventsResponse_ProcessExit:
		if ev.ProcessExit == nil || ev.ProcessExit.Process == nil {
			return nil
		}
		proc := ev.ProcessExit.Process
		events = append(events, sensor.Event{
			ID:        generateEventID(),
			Timestamp: time.Now(),
			Type:      sensor.EventTypeProcessExit,
			PID:       pidFromProcess(proc),
			ParentPID: pidFromProcess(ev.ProcessExit.Parent),
			Binary:    proc.Binary,
			ExitCode:  int32(ev.ProcessExit.Status),
		})

	case *tetragonAPI.GetEventsResponse_ProcessKprobe:
		if ev.ProcessKprobe == nil || ev.ProcessKprobe.Process == nil {
			return nil
		}
		kprobe := ev.ProcessKprobe
		proc := kprobe.Process

		switch {
		case isConnectKprobe(kprobe.FunctionName):
			destIP, destPort, proto := parseConnectArgs(kprobe.Args)
			events = append(events, sensor.Event{
				ID:        generateEventID(),
				Timestamp: time.Now(),
				Type:      sensor.EventTypeNetworkConnect,
				PID:       pidFromProcess(proc),
				ParentPID: pidFromProcess(kprobe.Parent),
				Binary:    proc.Binary,
				DestIP:    destIP,
				DestPort:  destPort,
				Protocol:  proto,
			})

		case isOpenKprobe(kprobe.FunctionName):
			filePath, flags := parseOpenArgs(kprobe.Args)
			events = append(events, sensor.Event{
				ID:         generateEventID(),
				Timestamp:  time.Now(),
				Type:       sensor.EventTypeFileAccess,
				PID:        pidFromProcess(proc),
				ParentPID:  pidFromProcess(kprobe.Parent),
				Binary:     proc.Binary,
				FilePath:   filePath,
				FileFlags:  flags,
				AccessType: accessTypeFromFlags(flags),
			})
		}
	}

	return events
}

// Helper functions

func generateEventID() string {
	return fmt.Sprintf("evt_%d", time.Now().UnixNano())
}

func startTimeFromProcess(proc *tetragonAPI.Process) time.Time {
	if proc.StartTime != nil {
		return proc.StartTime.AsTime()
	}
	return time.Now()
}

func pidFromProcess(proc *tetragonAPI.Process) uint32 {
	if proc != nil && proc.Pid != nil {
		return proc.Pid.GetValue()
	}
	return 0
}

func uidFromProcess(proc *tetragonAPI.Process) uint32 {
	if proc != nil && proc.Uid != nil {
		return proc.Uid.GetValue()
	}
	return 0
}

func splitArgs(args string) []string {
	if args == "" {
		return nil
	}
	return strings.Fields(args)
}

func isConnectKprobe(funcName string) bool {
	return funcName == "tcp_connect" || funcName == "__sys_connect" || funcName == "sys_connect"
}

func isOpenKprobe(funcName string) bool {
	return funcName == "do_sys_openat2" || funcName == "__x64_sys_openat" || funcName == "sys_openat"
}

func parseConnectArgs(args []*tetragonAPI.KprobeArgument) (net.IP, uint16, string) {
	for _, arg := range args {
		if sock := arg.GetSockArg(); sock != nil {
			ip := net.ParseIP(sock.Daddr)
			port := uint16(sock.Dport)
			proto := "tcp"
			if strings.EqualFold(sock.Protocol, "UDP") {
				proto = "udp"
			}
			return ip, port, proto
		}
	}
	return nil, 0, "tcp"
}

func parseOpenArgs(args []*tetragonAPI.KprobeArgument) (string, uint32) {
	var filePath string
	var flags uint32
	for _, arg := range args {
		if s := arg.GetStringArg(); s != "" {
			filePath = s
		}
		if f := arg.GetIntArg(); f != 0 {
			flags = uint32(f)
		}
	}
	return filePath, flags
}

func accessTypeFromFlags(flags uint32) string {
	switch {
	case flags&64 != 0: // O_CREAT
		return "create"
	case flags&2 != 0: // O_RDWR
		return "write"
	case flags&1 != 0: // O_WRONLY
		return "write"
	default:
		return "read"
	}
}
