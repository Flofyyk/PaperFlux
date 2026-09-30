package tunnel

import (
	"syscall"
	"time"
)

// Holding a kernel-bound socket reserves a source port across ALL workers and
// the host's ordinary sockets. An in-process allocator cannot provide that
// guarantee, even when virtual client addresses are distinct.
type clientFlowKey struct {
	flowKey
	clientIP [4]byte
}

func reserveNATPort(protocol byte) (int, uint16, error) {
	kind := syscall.SOCK_STREAM
	if protocol == 17 {
		kind = syscall.SOCK_DGRAM
	}
	fd, err := syscall.Socket(syscall.AF_INET, kind|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	if protocol == 17 {
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{}); err == nil {
		var address syscall.Sockaddr
		address, err = syscall.Getsockname(fd)
		if err == nil {
			return fd, uint16(address.(*syscall.SockaddrInet4).Port), nil
		}
	}
	syscall.Close(fd)
	return -1, 0, err
}

func (e *RawSocketEndpoint) claimFlow(original clientFlowKey, seq uint32, create, closing bool) (flowKey, flowState, bool) {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	if e.closed {
		return flowKey{}, flowState{}, false
	}
	if e.flowIndex == nil {
		e.flowIndex = make(map[clientFlowKey]flowKey)
	}
	key, exists := e.flowIndex[original]
	var state flowState
	if exists {
		value, ok := e.activeFlows.Load(key)
		if !ok {
			return flowKey{}, flowState{}, false
		}
		state = value.(flowState)
	} else {
		limit := e.maxFlows
		if limit == 0 {
			limit = configuredFlowLimit()
		}
		if !create || len(e.flowIndex) >= limit {
			e.flowRejected.Add(1)
			return flowKey{}, flowState{}, false
		}
		fd, port, err := reserveNATPort(original.protocol)
		if err != nil {
			e.flowRejected.Add(1)
			return flowKey{}, flowState{}, false
		}
		key = original.flowKey
		key.localPort = port
		state = flowState{clientIP: original.clientIP, original: original, reservation: fd}
		e.flowIndex[original] = key
	}
	state.seenAt = time.Now()
	if create && original.protocol == 6 {
		state.synSeq = seq
		state.closingAt = time.Time{}
	}
	// Keep FIN/RST mappings for delayed data and final ACKs. Deleting on the
	// first FIN used to cut off half-closed downloads and lose the last response.
	if closing && state.closingAt.IsZero() {
		state.closingAt = state.seenAt
	}
	e.activeFlows.Store(key, state)
	return key, state, true
}

func (e *RawSocketEndpoint) replyFlow(key flowKey, synACK bool, ack uint32) (flowState, bool) {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	value, ok := e.activeFlows.Load(key)
	if !ok || e.closed {
		return flowState{}, false
	}
	state := value.(flowState)
	if synACK && state.synSeq != ack-1 {
		return flowState{}, false
	}
	state.seenAt = time.Now()
	e.activeFlows.Store(key, state)
	return state, true
}

func (e *RawSocketEndpoint) pruneFlows(now time.Time, all bool) {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	if all {
		e.closed = true
	}
	e.activeFlows.Range(func(key, value any) bool {
		state := value.(flowState)
		ttl := 90 * time.Second
		if key.(flowKey).protocol == 6 {
			ttl = 5 * time.Minute
		}
		if all || now.Sub(state.seenAt) > ttl || (!state.closingAt.IsZero() && now.Sub(state.closingAt) > 30*time.Second) {
			e.activeFlows.Delete(key)
			delete(e.flowIndex, state.original)
			syscall.Close(state.reservation)
		}
		return true
	})
}
