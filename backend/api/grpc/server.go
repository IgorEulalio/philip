package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/philip-ai/philip/agent/sensor"
	"github.com/philip-ai/philip/backend/ingestion"
	"github.com/philip-ai/philip/backend/storage"
	pb "github.com/philip-ai/philip/pkg/proto/philip/v1"
	"google.golang.org/grpc"
)

// Server implements the AgentService gRPC server.
type Server struct {
	pb.UnimplementedAgentServiceServer
	store     storage.StoreInterface
	ingester  *ingestion.Handler
	logger    *slog.Logger
	grpcSrv   *grpc.Server
}

// NewServer creates a new gRPC server for agent communication.
func NewServer(store storage.StoreInterface, ingester *ingestion.Handler, logger *slog.Logger) *Server {
	return &Server{
		store:    store,
		ingester: ingester,
		logger:   logger,
	}
}

// Serve starts the gRPC server on the given address.
func (s *Server) Serve(address string) error {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.grpcSrv = grpc.NewServer()
	pb.RegisterAgentServiceServer(s.grpcSrv, s)

	s.logger.Info("gRPC server listening", "address", address)
	return s.grpcSrv.Serve(lis)
}

// Stop gracefully stops the gRPC server.
func (s *Server) Stop() {
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
	}
}

// RegisterAgent handles agent registration.
func (s *Server) RegisterAgent(ctx context.Context, req *pb.RegisterAgentRequest) (*pb.RegisterAgentResponse, error) {
	s.logger.Info("agent registered",
		"agent_id", req.AgentId,
		"hostname", req.Hostname,
		"sensor", req.SensorType)

	err := s.store.UpsertAgent(ctx, req.AgentId, req.Hostname, req.Version, req.SensorType)
	if err != nil {
		return nil, fmt.Errorf("storing agent: %w", err)
	}

	return &pb.RegisterAgentResponse{
		Accepted: true,
		Message:  "registered",
		Config: &pb.AgentConfig{
			RunnerProcessName:        "Runner.Worker",
			HeartbeatIntervalSeconds: 30,
			MaxEventsPerJob:          100000,
			EnabledEventTypes: []pb.EventType{
				pb.EventType_EVENT_TYPE_PROCESS_EXEC,
				pb.EventType_EVENT_TYPE_PROCESS_EXIT,
				pb.EventType_EVENT_TYPE_NETWORK_CONNECT,
			},
		},
	}, nil
}

// Heartbeat handles agent heartbeats.
func (s *Server) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	err := s.store.UpdateAgentHeartbeat(ctx, req.AgentId)
	if err != nil {
		s.logger.Warn("failed to update heartbeat", "agent_id", req.AgentId, "error", err)
	}
	return &pb.HeartbeatResponse{Ok: true}, nil
}

// SubmitJobEvents handles a complete job event record submission.
func (s *Server) SubmitJobEvents(ctx context.Context, req *pb.SubmitJobEventsRequest) (*pb.SubmitJobEventsResponse, error) {
	record := req.JobRecord
	if record == nil {
		return &pb.SubmitJobEventsResponse{Accepted: false, Message: "empty record"}, nil
	}

	metadata := ingestion.JobMetadata{}
	if record.Metadata != nil {
		metadata = ingestion.JobMetadata{
			Repository:   record.Metadata.Repository,
			WorkflowName: record.Metadata.WorkflowName,
			WorkflowFile: record.Metadata.WorkflowFile,
			RunID:        record.Metadata.RunId,
			RunNumber:    record.Metadata.RunNumber,
			Branch:       record.Metadata.Branch,
			CommitSHA:    record.Metadata.CommitSha,
			TriggerEvent: record.Metadata.TriggerEvent,
			RunnerName:   record.Metadata.RunnerName,
			RunnerOS:     record.Metadata.RunnerOs,
		}
	}

	// Convert proto events to sensor events
	events := make([]sensor.Event, 0, len(record.Events))
	for _, pbEvt := range record.Events {
		events = append(events, fromProtoEvent(pbEvt))
	}

	startTime := record.StartTime.AsTime()
	endTime := record.EndTime.AsTime()

	// Convert process tree
	processTree := make(map[string]interface{})
	for pid, info := range record.ProcessTree {
		processTree[fmt.Sprintf("%d", pid)] = map[string]interface{}{
			"binary": info.BinaryPath,
			"args":   info.Args,
		}
	}

	err := s.ingester.IngestJobRecord(ctx, record.JobId, metadata, events, startTime, endTime, processTree)
	if err != nil {
		return &pb.SubmitJobEventsResponse{
			Accepted: false,
			Message:  err.Error(),
		}, nil
	}

	return &pb.SubmitJobEventsResponse{
		Accepted: true,
		Message:  "ingested",
	}, nil
}

// StreamEvents handles streaming event submission.
func (s *Server) StreamEvents(stream pb.AgentService_StreamEventsServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		s.logger.Debug("received streamed events",
			"agent_id", req.AgentId,
			"count", len(req.Events))
	}
}

func fromProtoEvent(pbEvt *pb.Event) sensor.Event {
	evt := sensor.Event{
		ID:        pbEvt.Id,
		Timestamp: pbEvt.Timestamp.AsTime(),
		PID:       pbEvt.Pid,
		ParentPID: pbEvt.ParentPid,
		Binary:    pbEvt.BinaryPath,
		Args:      pbEvt.Args,
		CWD:       pbEvt.Cwd,
		UID:       pbEvt.Uid,
	}

	switch pbEvt.Type {
	case pb.EventType_EVENT_TYPE_PROCESS_EXEC:
		evt.Type = sensor.EventTypeProcessExec
	case pb.EventType_EVENT_TYPE_PROCESS_EXIT:
		evt.Type = sensor.EventTypeProcessExit
		if pbEvt.ProcessExit != nil {
			evt.ExitCode = pbEvt.ProcessExit.ExitCode
			evt.DurationMs = pbEvt.ProcessExit.DurationMs
		}
	case pb.EventType_EVENT_TYPE_NETWORK_CONNECT:
		evt.Type = sensor.EventTypeNetworkConnect
		if pbEvt.NetworkConnect != nil {
			evt.DestIP = net.ParseIP(pbEvt.NetworkConnect.DestIp)
			evt.DestPort = uint16(pbEvt.NetworkConnect.DestPort)
			evt.Protocol = pbEvt.NetworkConnect.Protocol
		}
	case pb.EventType_EVENT_TYPE_FILE_ACCESS:
		evt.Type = sensor.EventTypeFileAccess
		if pbEvt.FileAccess != nil {
			evt.FilePath = pbEvt.FileAccess.FilePath
			evt.FileFlags = pbEvt.FileAccess.Flags
			evt.AccessType = pbEvt.FileAccess.AccessType
		}
	}

	return evt
}
