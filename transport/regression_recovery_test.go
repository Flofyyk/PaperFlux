package transport

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"universal-bypass-tool/transport/control"
)

func TestMultiBusyLanesStillAdmitPacket(t *testing.T) {
	peer := &memoryTransport{}
	_ = peer.Start()
	got := make(chan struct{}, 1)
	peer.Receive(func([]byte) { got <- struct{}{} })
	lane := &healthMemoryTransport{memoryTransport: memoryTransport{peer: peer, running: true}, health: LaneHealth{Connected: true, QueueLoad: 1}}
	m := NewMultiTransport([]Transport{lane}, DefaultConfig())
	if err := m.Send(testIPv4(40, 6)); err != nil {
		t.Fatal("busy lane was skipped:", err)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("packet lost")
	}
}

func TestSessionControlAdmissionFailureUsesAlternateCarrier(t *testing.T) {
	client, exit, _, _ := linkedSessions(t, "first", "second")
	startPair(t, client, exit)
	defer client.Stop()
	defer exit.Stop()
	got := make(chan string, 1)
	exit.SetControlHandler(func(sub control.Subtype, payload []byte) {
		if sub == control.SubtypeCookiesRequest {
			got <- string(payload)
		}
	})
	client.links["first"].batched.running.Store(false)
	if err := client.SendControl(control.SubtypeCookiesRequest, []byte("request")); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-got:
		if value != "request" {
			t.Fatal("control payload changed")
		}
	case <-time.After(time.Second):
		t.Fatal("control lost on first carrier")
	}
}

func TestEditorPayloadsPreserveMixedRecords(t *testing.T) {
	text := `42["message",{"messages":[{"cursor":"18;---KA---"},{"cursor" : "18;YQ=="},{"excelAdditionalInfo":"Yg=="},{"cursor":"18;---KA---"},{"cursor":"18;Yw=="}]}]`
	if got := EditorPayloads(text); !reflect.DeepEqual(got, []string{"YQ==", "Yg==", "Yw=="}) {
		t.Fatalf("payloads = %v", got)
	}
}

func TestBatchManyWaitersStopWithinDeadline(t *testing.T) {
	b := newBatchedTransportWithBudget(&fakeTransport{}, 4)
	b.queue = make(chan []byte, 1)
	b.running.Store(true)
	b.admitTimeout = time.Second
	if err := b.Send([]byte("full")); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := b.Send([]byte("next")); err == nil {
				t.Error("stopped queue admitted waiter")
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	_ = b.Stop()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiters deadlocked during stop")
	}
}

func TestSessionAdmissionFailureUsesAlternateCarrier(t *testing.T) {
	client, exit, _, _ := linkedSessions(t, "first", "second")
	startPair(t, client, exit)
	defer client.Stop()
	defer exit.Stop()
	got := make(chan struct{}, 1)
	exit.Receive(func([]byte) {
		select {
		case got <- struct{}{}:
		default:
		}
	})
	packet := testIPv4(40, 6)
	flow := extractFlowKeyBytes(packet)
	key := string(flow[:])
	// A carrier can remain attached while its local admission has stopped.
	client.selector.rememberFlow(key, "first")
	client.links["first"].batched.running.Store(false)
	if err := client.Send(packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(time.Second):
		t.Fatal("alternate carrier did not deliver")
	}
}

func BenchmarkLaneSelectorPinned(b *testing.B) {
	var s laneSelector
	lanes := []laneCandidate{{name: "a", health: LaneHealth{Connected: true, RTT: 300 * time.Millisecond}}, {name: "b", health: LaneHealth{Connected: true, RTT: 400 * time.Millisecond}}}
	now := time.Now()
	_ = s.pick(lanes, "flow", 0, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.pick(lanes, "flow", 0, now)
	}
}

func TestReplay4096RingBoundaries(t *testing.T) {
	s := &Session{}
	for _, seq := range []uint64{1, 4000, 2, 3999} {
		if !s.acceptSequenceLocked(seq) {
			t.Fatalf("rejected fresh %d", seq)
		}
	}
	for _, seq := range []uint64{0, 1, 2, 3999, 4000} {
		if s.acceptSequenceLocked(seq) {
			t.Fatalf("accepted replay %d", seq)
		}
	}
	if !s.acceptSequenceLocked(8096) {
		t.Fatal("advance failed")
	}
	if s.acceptSequenceLocked(4000) {
		t.Fatal("expired sequence accepted")
	}
	if !s.acceptSequenceLocked(4001) || s.acceptSequenceLocked(4001) {
		t.Fatal("ring boundary incorrect")
	}
	if !s.acceptSequenceLocked(^uint64(0)) || s.acceptSequenceLocked(^uint64(0)) {
		t.Fatal("overflow boundary incorrect")
	}
}

func TestBatchCapacityWaitReleaseTimeoutAndStop(t *testing.T) {
	for _, mode := range []string{"space", "timeout", "stop"} {
		t.Run(mode, func(t *testing.T) {
			b := newBatchedTransportWithBudget(&fakeTransport{}, 4)
			b.queue = make(chan []byte, 1)
			b.admitTimeout = 80 * time.Millisecond
			// Admission-only harness: no consumer unless explicitly released.
			b.running.Store(true)
			if err := b.Send([]byte("abcd")); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- b.Send([]byte("next")) }()
			select {
			case <-done:
				t.Fatal("full queue did not wait")
			case <-time.After(15 * time.Millisecond):
			}
			switch mode {
			case "space":
				b.releaseQueuePacket(<-b.queue)
			case "stop":
				_ = b.Stop()
			}
			select {
			case err := <-done:
				if (err == nil) != (mode == "space") {
					t.Fatalf("unexpected result: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("admission stuck")
			}
			if b.Stats().QueueWaits != 1 {
				t.Fatal("wait not counted")
			}
			if mode == "timeout" && b.Stats().QueueTimeouts != 1 {
				t.Fatal("timeout not counted")
			}
			_ = b.Stop()
			if b.queueBytes.Load() != 0 {
				t.Fatal("queue budget leaked")
			}
		})
	}
}

func TestLaneSelectorPinFailureRecoveryAndEmergency(t *testing.T) {
	var selector laneSelector
	now := time.Now()
	lanes := []laneCandidate{{name: "a", health: LaneHealth{Connected: true, RTT: 300 * time.Millisecond}}, {name: "b", health: LaneHealth{Connected: true, RTT: 300 * time.Millisecond}}}
	picked := selector.pick(lanes, "flow", 0, now)
	other := 1 - picked
	lanes[picked].health.QueueLoad = .8
	if got := selector.pick(lanes, "flow", 0, now.Add(time.Second)); got != picked {
		t.Fatal("healthy flow migrated")
	}
	lanes[picked].health.Connected = false
	if got := selector.pick(lanes, "flow", 0, now.Add(2*time.Second)); got != other {
		t.Fatal("failed flow did not migrate")
	}
	lanes[picked].health = LaneHealth{Connected: true, RTT: time.Millisecond}
	_ = selector.pick(lanes, "", 0, now.Add(3*time.Second))
	if !selector.isDemoted(lanes[picked].name) {
		t.Fatal("recovery hold skipped")
	}
	_ = selector.pick(lanes, "", 0, now.Add(6*time.Second))
	if selector.isDemoted(lanes[picked].name) {
		t.Fatal("healthy recovery never promoted")
	}
	for i := range lanes {
		lanes[i].health.QueueLoad = 1
	}
	_ = selector.pick(lanes, "", 0, now.Add(7*time.Second))
	if got := selector.pick(lanes, "", 0, now.Add(11*time.Second)); got < 0 {
		t.Fatal("all-demoted pool lost emergency connectivity")
	}
}

func TestLaneSelectorSmoothsSpikeAndWeightsRate(t *testing.T) {
	var selector laneSelector
	now := time.Now()
	lanes := []laneCandidate{{name: "a", health: LaneHealth{Connected: true, RTT: 100 * time.Millisecond}}, {name: "b", health: LaneHealth{Connected: true, RTT: 100 * time.Millisecond}}}
	_ = selector.pick(lanes, "", 0, now)
	lanes[0].health.RTT = 1000 * time.Millisecond
	lanes[1].stats.BytesReceived = 100000
	if got := selector.pick(lanes, "", 0, now.Add(time.Second)); got != 1 {
		t.Fatal("rate/latency not used")
	}
	if selector.samples["a"].rtt >= 1000 || selector.isDemoted("a") {
		t.Fatal("single spike caused demotion")
	}
}

func TestLaneSelectorKeepsWorkingLowerPriorityFallback(t *testing.T) {
	var selector laneSelector
	now := time.Now()
	lanes := []laneCandidate{
		{name: "primary", priority: 100, health: LaneHealth{Connected: true}},
		{name: "backup", priority: 10, health: LaneHealth{Connected: true}},
	}
	if got := selector.pick(lanes, "new", 0, now); got != 0 {
		t.Fatal("new flow ignored priority")
	}
	selector.rememberFlow("failed-over", "backup")
	if got := selector.pick(lanes, "failed-over", 0, now); got != 1 {
		t.Fatal("working fallback sent back to congested primary")
	}
	lanes[1].health.Connected = false
	if got := selector.pick(lanes, "failed-over", 0, now); got != 0 {
		t.Fatal("disconnected fallback stayed pinned")
	}
}
