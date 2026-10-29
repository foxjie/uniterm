package session

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// Tests for the async, bounded emit path (issue #1053): a flood of terminal
// output must never block the session's readLoop against the synchronous
// Wails event emit, and high-frequency chunks should be coalesced before they
// cross the IPC boundary.
//
// Overflow policy is two-tier: while the consumer is merely slow the producer
// blocks (flow control — a full-screen TUI only sends diffs, so dropped bytes
// would desync the screen), and only after a watchdog expires does it degrade
// to drop-oldest so a wedged frontend cannot freeze the readLoop.

func TestEmitDataSyncWhenLoopNotStarted(t *testing.T) {
	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
	})

	s.emitData([]byte("hello"))

	mu.Lock()
	defer mu.Unlock()
	if string(got) != "hello" {
		t.Fatalf("emitData without emitLoop delivered %q synchronously, want %q", got, "hello")
	}
}

func TestEmitDataBatchesWhenLoopStarted(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 40 * time.Millisecond
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	calls := 0
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
		calls++
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)

	const n = 50
	for i := 0; i < n; i++ {
		s.emitData([]byte("x"))
	}
	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("delivered %d bytes, want %d (no loss)", len(got), n)
	}
	if bytes.Count(got, []byte("x")) != n {
		t.Fatalf("delivered content %q is corrupted", got)
	}
	if calls >= n {
		t.Fatalf("callback ran %d times for %d chunks; batching did not happen", calls, n)
	}
}

func TestEmitDataDropsOldestWhenQueueFull(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Second
	t.Cleanup(func() { emitFlushInterval = oldInterval })
	oldWatchdog := emitBlockWatchdog
	emitBlockWatchdog = 100 * time.Millisecond
	t.Cleanup(func() { emitBlockWatchdog = oldWatchdog })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	delivered := make(chan struct{}, 1)
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		got = append(got, data...)
		mu.Unlock()
		select {
		case delivered <- struct{}{}:
		default:
		}
	})
	s.startEmitLoop()

	// The idle→busy fast path delivers the first chunk before any batch
	// window opens; wait for it so the queue-full phase below deterministically
	// starts from an empty queue.
	s.emitData([]byte{0})
	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle first chunk was never flushed")
	}

	// Enqueue well past the queue capacity while the (5s) window is closed:
	// the oldest queued chunks must be dropped, keeping the newest.
	for i := 1; i < emitQueueCapacity+10; i++ {
		s.emitData([]byte{byte(i)})
	}
	// stopEmitLoop force-flushes whatever survived in the queue.
	s.stopEmitLoop()

	mu.Lock()
	defer mu.Unlock()
	want := []byte{0}
	for i := 10; i < emitQueueCapacity+10; i++ {
		want = append(want, byte(i))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("delivered %v, want chunk 0 then chunks %d..%d in order (drop-oldest)", got, 10, emitQueueCapacity+9)
	}
}

func TestEmitDataSyncDuringZmodem(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Second
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)
	s.SetZmodemMode(true)

	s.emitData([]byte("zmodem payload"))

	mu.Lock()
	defer mu.Unlock()
	if string(got) != "zmodem payload" {
		t.Fatalf("emitData during zmodem delivered %q synchronously, want %q", got, "zmodem payload")
	}
}

func TestStopEmitLoopFlushesPending(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Second
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
	})
	s.startEmitLoop()

	s.emitData([]byte("tail"))
	s.stopEmitLoop()

	mu.Lock()
	if string(got) != "tail" {
		mu.Unlock()
		t.Fatalf("stopEmitLoop delivered %q, want pending %q flushed", got, "tail")
	}
	mu.Unlock()

	// After the loop stopped, emitData must fall back to the synchronous path.
	s.emitData([]byte("sync"))
	mu.Lock()
	if string(got) != "tailsync" {
		mu.Unlock()
		t.Fatalf("emitData after stop delivered %q, want %q", got, "tailsync")
	}
	mu.Unlock()
}

func TestEmitDataDoesNotBlockOnSlowConsumer(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 40 * time.Millisecond
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	blocked := make(chan struct{})
	release := make(chan struct{})
	signalOnce := &sync.Once{}
	s.SetOnDataCallback(func(data []byte) {
		signalOnce.Do(func() { close(blocked) })
		<-release
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)

	s.emitData([]byte("first"))

	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("callback was never invoked")
	}

	done := make(chan struct{})
	go func() {
		s.emitData([]byte("second"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emitData blocked on a stuck consumer; readLoop would freeze")
	}
	close(release)
}

// Flow control: while the consumer is merely slow (but still draining), the
// producer must block instead of dropping bytes. A full-screen TUI such as
// menuconfig only sends diffs after its initial paint, so losing a chunk
// desyncs the screen permanently.
func TestEmitDataNoLossWhenConsumerSlow(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Millisecond
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	s.SetOnDataCallback(func(data []byte) {
		time.Sleep(10 * time.Millisecond) // simulate a busy frontend
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)

	const n = emitQueueCapacity + 16
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < n; i++ {
			s.emitData([]byte{byte(i)})
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("producer never finished; flow control wedged the readLoop")
	}
	// Let the emit loop drain the tail of the queue.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("delivered %d bytes, want %d (transient consumer lag must not lose bytes)", len(got), n)
	}
	for i := 0; i < n; i++ {
		if got[i] != byte(i) {
			t.Fatalf("byte %d corrupted: got %d", i, got[i])
		}
	}
	s.emitMu.Lock()
	dropped := s.emitDropped
	s.emitMu.Unlock()
	if dropped != 0 {
		t.Fatalf("dropped %d chunk(s); transient consumer lag must not lose bytes", dropped)
	}
}

// Watchdog: when the consumer is wedged (not draining at all), the producer
// must degrade to drop-oldest instead of blocking forever — the freeze
// protection for a wedged frontend stays intact.
func TestEmitDataWedgeFallsBackToDropOldest(t *testing.T) {
	oldWatchdog := emitBlockWatchdog
	emitBlockWatchdog = 100 * time.Millisecond
	t.Cleanup(func() { emitBlockWatchdog = oldWatchdog })
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Second
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	var mu sync.Mutex
	var got []byte
	entered := make(chan struct{})
	once := &sync.Once{}
	release := make(chan struct{})
	s.SetOnDataCallback(func(data []byte) {
		once.Do(func() { close(entered) })
		<-release
		mu.Lock()
		defer mu.Unlock()
		got = append(got, data...)
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)

	// The idle→busy fast path delivers chunk 0 into the wedged consumer, so
	// the overflow phase below starts from an empty queue and the drop count
	// is deterministic (chunk 0 is delivered, not dropped).
	s.emitData([]byte{0})
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("idle first chunk never reached the consumer")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 1; i < emitQueueCapacity+10; i++ {
			s.emitData([]byte{byte(i)})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("producer never degraded to drop-oldest; readLoop would freeze")
	}

	// Read the drop counter before releasing/stopping: the force-flush drains
	// the queue and resets the counter (after logging the overflow).
	s.emitMu.Lock()
	dropped := s.emitDropped
	s.emitMu.Unlock()
	if dropped != 9 {
		t.Fatalf("dropped %d chunks, want 9", dropped)
	}
	close(release)

	s.stopEmitLoop()

	mu.Lock()
	defer mu.Unlock()
	want := []byte{0}
	for i := 10; i < emitQueueCapacity+10; i++ {
		want = append(want, byte(i))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("delivered %v, want chunk 0 then chunks %d..%d (drop-oldest after watchdog)", got, 10, emitQueueCapacity+9)
	}
}

// Latency: an isolated chunk after an idle gap must not wait out the batch
// window — interactive echoes pay only the IPC, not the coalescing delay.
func TestEmitDataIdleFirstChunkFlushesImmediately(t *testing.T) {
	oldInterval := emitFlushInterval
	emitFlushInterval = 5 * time.Second
	t.Cleanup(func() { emitFlushInterval = oldInterval })

	s := &baseSession{}
	delivered := make(chan time.Duration, 1)
	start := time.Now()
	s.SetOnDataCallback(func(data []byte) {
		delivered <- time.Since(start)
	})
	s.startEmitLoop()
	t.Cleanup(s.stopEmitLoop)

	s.emitData([]byte("ping"))
	select {
	case elapsed := <-delivered:
		if elapsed > 500*time.Millisecond {
			t.Fatalf("idle chunk waited %s; the batch window was not skipped", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle chunk was never delivered")
	}
}

// Coalescing must not produce payloads that cross Wails' inline event limit:
// oversized flushes are split into emitFlushMaxBytes pieces, in order, lossless.
func TestFlushEmitChunksCapsCallbackPayloadSize(t *testing.T) {
	oldCap := emitFlushMaxBytes
	emitFlushMaxBytes = 100
	t.Cleanup(func() { emitFlushMaxBytes = oldCap })

	s := &baseSession{}
	var mu sync.Mutex
	var sizes []int
	var got []byte
	s.SetOnDataCallback(func(data []byte) {
		mu.Lock()
		defer mu.Unlock()
		sizes = append(sizes, len(data))
		got = append(got, data...)
	})

	chunks := [][]byte{}
	for i := 0; i < 5; i++ {
		chunks = append(chunks, bytes.Repeat([]byte{byte(i)}, 60)) // 300 total
	}
	// Also covers the single oversized chunk path.
	s.flushEmitChunks(chunks)
	s.flushEmitChunks([][]byte{bytes.Repeat([]byte{9}, 250)})

	mu.Lock()
	defer mu.Unlock()
	wantSizes := []int{100, 100, 100, 100, 100, 50}
	if len(sizes) != len(wantSizes) {
		t.Fatalf("callback sizes %v, want %v", sizes, wantSizes)
	}
	for i, w := range wantSizes {
		if sizes[i] != w {
			t.Fatalf("callback %d size %d, want %d", i, sizes[i], w)
		}
	}
	if len(got) != 550 {
		t.Fatalf("delivered %d bytes, want 550 (lossless split)", len(got))
	}
}
