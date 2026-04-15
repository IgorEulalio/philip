package collector

import (
	"sync"

	"github.com/IgorEulalio/philip/agent/sensor"
)

// ProcessNode represents a single process in the tree.
type ProcessNode struct {
	PID       uint32
	ParentPID uint32
	Binary    string
	Args      []string
	CWD       string
	Children  []uint32
	ExitCode  *int32
}

// ProcessTree tracks the full process hierarchy for a CI/CD job run.
// It is rooted at the runner process and includes all descendants.
type ProcessTree struct {
	mu       sync.RWMutex
	nodes    map[uint32]*ProcessNode
	rootPID  uint32
	rootSet  bool
}

// NewProcessTree creates an empty process tree.
func NewProcessTree() *ProcessTree {
	return &ProcessTree{
		nodes: make(map[uint32]*ProcessNode),
	}
}

// SetRoot sets the root PID of the tree (the CI/CD runner process).
func (pt *ProcessTree) SetRoot(pid uint32) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.rootPID = pid
	pt.rootSet = true
}

// RootPID returns the root PID, if set.
func (pt *ProcessTree) RootPID() (uint32, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return pt.rootPID, pt.rootSet
}

// HandleEvent updates the process tree based on a sensor event.
func (pt *ProcessTree) HandleEvent(evt sensor.Event) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	switch evt.Type {
	case sensor.EventTypeProcessExec:
		node := &ProcessNode{
			PID:       evt.PID,
			ParentPID: evt.ParentPID,
			Binary:    evt.Binary,
			Args:      evt.Args,
			CWD:       evt.CWD,
		}
		pt.nodes[evt.PID] = node

		// Link to parent
		if parent, ok := pt.nodes[evt.ParentPID]; ok {
			parent.Children = append(parent.Children, evt.PID)
		}

	case sensor.EventTypeProcessExit:
		if node, ok := pt.nodes[evt.PID]; ok {
			exitCode := evt.ExitCode
			node.ExitCode = &exitCode
		}
	}
}

// IsDescendant checks if a PID is a descendant of the root runner process.
func (pt *ProcessTree) IsDescendant(pid uint32) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if !pt.rootSet {
		return false
	}
	if pid == pt.rootPID {
		return true
	}

	// Walk up the parent chain
	visited := make(map[uint32]bool)
	current := pid
	for {
		if current == pt.rootPID {
			return true
		}
		if visited[current] {
			return false // cycle protection
		}
		visited[current] = true

		node, ok := pt.nodes[current]
		if !ok {
			return false
		}
		current = node.ParentPID
	}
}

// GetAncestry returns the process chain from pid up to root.
func (pt *ProcessTree) GetAncestry(pid uint32) []ProcessNode {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	var chain []ProcessNode
	visited := make(map[uint32]bool)
	current := pid

	for {
		if visited[current] {
			break
		}
		visited[current] = true

		node, ok := pt.nodes[current]
		if !ok {
			break
		}
		chain = append(chain, *node)
		if current == pt.rootPID {
			break
		}
		current = node.ParentPID
	}

	return chain
}

// GetNode returns a copy of a process node by PID.
func (pt *ProcessTree) GetNode(pid uint32) (ProcessNode, bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	node, ok := pt.nodes[pid]
	if !ok {
		return ProcessNode{}, false
	}
	return *node, true
}

// AllNodes returns a snapshot of all nodes in the tree.
func (pt *ProcessTree) AllNodes() map[uint32]ProcessNode {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	result := make(map[uint32]ProcessNode, len(pt.nodes))
	for pid, node := range pt.nodes {
		result[pid] = *node
	}
	return result
}

// Size returns the number of processes in the tree.
func (pt *ProcessTree) Size() int {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	return len(pt.nodes)
}
