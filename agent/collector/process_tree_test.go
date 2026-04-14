package collector

import (
	"testing"

	"github.com/philip-ai/philip/agent/sensor"
)

func TestProcessTree_HandleEvent(t *testing.T) {
	tests := []struct {
		name       string
		events     []sensor.Event
		wantSize   int
		wantPIDs   []uint32
	}{
		{
			name:     "empty tree",
			events:   nil,
			wantSize: 0,
		},
		{
			name: "single process exec",
			events: []sensor.Event{
				{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/bin/bash"},
			},
			wantSize: 1,
			wantPIDs: []uint32{100},
		},
		{
			name: "parent child relationship",
			events: []sensor.Event{
				{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/bin/bash"},
				{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/usr/bin/npm"},
			},
			wantSize: 2,
			wantPIDs: []uint32{100, 200},
		},
		{
			name: "process exit updates node",
			events: []sensor.Event{
				{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/bin/bash"},
				{Type: sensor.EventTypeProcessExit, PID: 100, ExitCode: 0},
			},
			wantSize: 1,
			wantPIDs: []uint32{100},
		},
		{
			name: "non-exec events do not create nodes",
			events: []sensor.Event{
				{Type: sensor.EventTypeNetworkConnect, PID: 100, ParentPID: 1},
			},
			wantSize: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pt := NewProcessTree()
			for _, evt := range tc.events {
				pt.HandleEvent(evt)
			}

			if got := pt.Size(); got != tc.wantSize {
				t.Errorf("Size() = %d, want %d", got, tc.wantSize)
			}

			for _, pid := range tc.wantPIDs {
				if _, ok := pt.GetNode(pid); !ok {
					t.Errorf("GetNode(%d) not found, expected it to exist", pid)
				}
			}
		})
	}
}

func TestProcessTree_HandleEvent_ExitCode(t *testing.T) {
	pt := NewProcessTree()
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, Binary: "/bin/bash"})
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExit, PID: 100, ExitCode: 42})

	node, ok := pt.GetNode(100)
	if !ok {
		t.Fatal("node not found")
	}
	if node.ExitCode == nil {
		t.Fatal("ExitCode is nil, expected 42")
	}
	if *node.ExitCode != 42 {
		t.Errorf("ExitCode = %d, want 42", *node.ExitCode)
	}
}

func TestProcessTree_HandleEvent_ChildrenLinked(t *testing.T) {
	pt := NewProcessTree()
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/bin/bash"})
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/usr/bin/npm"})
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 300, ParentPID: 100, Binary: "/usr/bin/node"})

	parent, _ := pt.GetNode(100)
	if len(parent.Children) != 2 {
		t.Errorf("parent has %d children, want 2", len(parent.Children))
	}
}

func TestProcessTree_IsDescendant(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(pt *ProcessTree)
		pid    uint32
		want   bool
	}{
		{
			name: "root itself is a descendant",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, Binary: "/runner"})
			},
			pid:  100,
			want: true,
		},
		{
			name: "direct child is descendant",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/runner"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/bin/bash"})
			},
			pid:  200,
			want: true,
		},
		{
			name: "grandchild is descendant",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/runner"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/bin/bash"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 300, ParentPID: 200, Binary: "/usr/bin/npm"})
			},
			pid:  300,
			want: true,
		},
		{
			name: "unrelated process is not descendant",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/runner"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 999, ParentPID: 50, Binary: "/other"})
			},
			pid:  999,
			want: false,
		},
		{
			name: "unknown PID is not descendant",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
			},
			pid:  42,
			want: false,
		},
		{
			name: "no root set returns false",
			setup: func(pt *ProcessTree) {
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, Binary: "/runner"})
			},
			pid:  100,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pt := NewProcessTree()
			tc.setup(pt)

			if got := pt.IsDescendant(tc.pid); got != tc.want {
				t.Errorf("IsDescendant(%d) = %v, want %v", tc.pid, got, tc.want)
			}
		})
	}
}

func TestProcessTree_GetAncestry(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(pt *ProcessTree)
		pid       uint32
		wantLen   int
		wantFirst uint32 // first PID in chain (the queried PID)
		wantLast  uint32 // last PID in chain (closest to root)
	}{
		{
			name: "single node ancestry",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, Binary: "/runner"})
			},
			pid:       100,
			wantLen:   1,
			wantFirst: 100,
			wantLast:  100,
		},
		{
			name: "three-level ancestry",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, ParentPID: 1, Binary: "/runner"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 200, ParentPID: 100, Binary: "/bin/bash"})
				pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 300, ParentPID: 200, Binary: "/usr/bin/npm"})
			},
			pid:       300,
			wantLen:   3,
			wantFirst: 300,
			wantLast:  100,
		},
		{
			name: "unknown PID returns empty",
			setup: func(pt *ProcessTree) {
				pt.SetRoot(100)
			},
			pid:     42,
			wantLen: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pt := NewProcessTree()
			tc.setup(pt)

			chain := pt.GetAncestry(tc.pid)
			if len(chain) != tc.wantLen {
				t.Fatalf("GetAncestry(%d) returned %d nodes, want %d", tc.pid, len(chain), tc.wantLen)
			}
			if tc.wantLen > 0 {
				if chain[0].PID != tc.wantFirst {
					t.Errorf("first ancestor PID = %d, want %d", chain[0].PID, tc.wantFirst)
				}
				if chain[len(chain)-1].PID != tc.wantLast {
					t.Errorf("last ancestor PID = %d, want %d", chain[len(chain)-1].PID, tc.wantLast)
				}
			}
		})
	}
}

func TestProcessTree_AllNodes(t *testing.T) {
	pt := NewProcessTree()
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 100, Binary: "/a"})
	pt.HandleEvent(sensor.Event{Type: sensor.EventTypeProcessExec, PID: 200, Binary: "/b"})

	nodes := pt.AllNodes()
	if len(nodes) != 2 {
		t.Fatalf("AllNodes() returned %d nodes, want 2", len(nodes))
	}

	// Verify it's a copy — modifying shouldn't affect the tree
	nodes[100] = ProcessNode{PID: 999}
	original, _ := pt.GetNode(100)
	if original.PID != 100 {
		t.Error("AllNodes() returned a reference instead of a copy")
	}
}
