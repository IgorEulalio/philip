package transport

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/philip-ai/philip/agent/collector"
	"github.com/philip-ai/philip/agent/sensor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/philip-ai/philip/pkg/proto/philip/v1"
)

// BackendClient ships job event records to the Philip backend.
type BackendClient struct {
	conn    *grpc.ClientConn
	client  pb.AgentServiceClient
	agentID string
	logger  *slog.Logger
}

// NewBackendClient creates a new gRPC client for the backend.
func NewBackendClient(address string, agentID string, logger *slog.Logger) (*BackendClient, error) {
	// TODO: add TLS support
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to backend: %w", err)
	}

	return &BackendClient{
		conn:    conn,
		client:  pb.NewAgentServiceClient(conn),
		agentID: agentID,
		logger:  logger,
	}, nil
}

// Register registers this agent with the backend.
func (bc *BackendClient) Register(ctx context.Context, hostname, version, sensorType string) error {
	_, err := bc.client.RegisterAgent(ctx, &pb.RegisterAgentRequest{
		AgentId:       bc.agentID,
		Hostname:      hostname,
		Version:       version,
		SensorType:    sensorType,
		StartedAt:     timestamppb.Now(),
	})
	if err != nil {
		return fmt.Errorf("registering agent: %w", err)
	}
	bc.logger.Info("registered with backend", "agent_id", bc.agentID)
	return nil
}

// SubmitJobRecord ships a complete job event record to the backend.
func (bc *BackendClient) SubmitJobRecord(ctx context.Context, record collector.JobEventRecord) error {
	pbRecord := toProtoJobRecord(record)

	resp, err := bc.client.SubmitJobEvents(ctx, &pb.SubmitJobEventsRequest{
		JobRecord: pbRecord,
	})
	if err != nil {
		return fmt.Errorf("submitting job events: %w", err)
	}

	bc.logger.Info("submitted job record",
		"job_id", record.JobID,
		"accepted", resp.Accepted,
		"deviations", len(resp.Deviations))

	return nil
}

// Heartbeat sends a heartbeat to the backend.
func (bc *BackendClient) Heartbeat(ctx context.Context, status *pb.AgentStatus) error {
	_, err := bc.client.Heartbeat(ctx, &pb.HeartbeatRequest{
		AgentId: bc.agentID,
		Status:  status,
	})
	return err
}

// Close closes the gRPC connection.
func (bc *BackendClient) Close() error {
	return bc.conn.Close()
}

// RunHeartbeat sends periodic heartbeats to the backend.
func (bc *BackendClient) RunHeartbeat(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := bc.Heartbeat(ctx, &pb.AgentStatus{}); err != nil {
				bc.logger.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

// toProtoJobRecord converts an internal JobEventRecord to the protobuf type.
func toProtoJobRecord(record collector.JobEventRecord) *pb.JobEventRecord {
	pbEvents := make([]*pb.Event, 0, len(record.Events))
	for _, evt := range record.Events {
		pbEvents = append(pbEvents, toProtoEvent(evt))
	}

	pbTree := make(map[uint32]*pb.ProcessInfo)
	for pid, node := range record.Tree {
		pbTree[pid] = &pb.ProcessInfo{
			Pid:        pid,
			BinaryPath: node.Binary,
			Args:       node.Args,
		}
	}

	return &pb.JobEventRecord{
		JobId: record.JobID,
		Metadata: &pb.JobMetadata{
			Repository:   record.Metadata.Repository,
			WorkflowName: record.Metadata.WorkflowName,
			WorkflowFile: record.Metadata.WorkflowFile,
			RunId:        record.Metadata.RunID,
			RunNumber:    record.Metadata.RunNumber,
			Branch:       record.Metadata.Branch,
			CommitSha:    record.Metadata.CommitSHA,
			TriggerEvent: record.Metadata.TriggerEvent,
			RunnerName:   record.Metadata.RunnerName,
			RunnerOs:     record.Metadata.RunnerOS,
		},
		Events:      pbEvents,
		StartTime:   timestamppb.New(record.StartTime),
		EndTime:     timestamppb.New(record.EndTime),
		ProcessTree: pbTree,
	}
}

func toProtoEvent(evt sensor.Event) *pb.Event {
	pbEvt := &pb.Event{
		Id:        evt.ID,
		Timestamp: timestamppb.New(evt.Timestamp),
		Pid:       evt.PID,
		ParentPid: evt.ParentPID,
		BinaryPath: evt.Binary,
		Args:      evt.Args,
		Cwd:       evt.CWD,
		Uid:       evt.UID,
	}

	switch evt.Type {
	case sensor.EventTypeProcessExec:
		pbEvt.Type = pb.EventType_EVENT_TYPE_PROCESS_EXEC
		pbEvt.ProcessExec = &pb.ProcessExecEvent{
			BinaryPath: evt.Binary,
			Args:       evt.Args,
		}
	case sensor.EventTypeProcessExit:
		pbEvt.Type = pb.EventType_EVENT_TYPE_PROCESS_EXIT
		pbEvt.ProcessExit = &pb.ProcessExitEvent{
			ExitCode:   evt.ExitCode,
			DurationMs: evt.DurationMs,
		}
	case sensor.EventTypeNetworkConnect:
		pbEvt.Type = pb.EventType_EVENT_TYPE_NETWORK_CONNECT
		destIP := ""
		if evt.DestIP != nil {
			destIP = evt.DestIP.String()
		}
		pbEvt.NetworkConnect = &pb.NetworkConnectEvent{
			DestIp:   destIP,
			DestPort: uint32(evt.DestPort),
			Protocol: evt.Protocol,
		}
	case sensor.EventTypeFileAccess:
		pbEvt.Type = pb.EventType_EVENT_TYPE_FILE_ACCESS
		pbEvt.FileAccess = &pb.FileAccessEvent{
			FilePath:   evt.FilePath,
			Flags:      evt.FileFlags,
			AccessType: evt.AccessType,
		}
	}

	return pbEvt
}
