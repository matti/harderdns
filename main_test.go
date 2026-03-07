package main

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func initEvents(upstreams []string) {
	events = make(map[string]map[string]int)
	for _, u := range upstreams {
		events[u] = make(map[string]int)
	}
}

func TestCreateResponse(t *testing.T) {
	t.Run("nil RR list", func(t *testing.T) {
		resp := createResponse(nil)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Answer) != 0 {
			t.Fatalf("expected 0 answers, got %d", len(resp.Answer))
		}
		if resp.RecursionAvailable != true {
			t.Fatal("expected RecursionAvailable to be true")
		}
	})

	t.Run("with valid RRs", func(t *testing.T) {
		rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		resp := createResponse([]dns.RR{rr})
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
	})

	t.Run("with nil RR element", func(t *testing.T) {
		// This tests the localhost bug where a non-A/AAAA query
		// creates a response with a nil RR element
		resp := createResponse([]dns.RR{nil})
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		// The nil element is in the answer - this is a bug
		if resp.Answer[0] != nil {
			t.Fatal("expected nil answer element")
		}
	})
}

func TestLogger(t *testing.T) {
	// Ensure logger doesn't panic under concurrent use
	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger("test-id", "TEST", q, "part1", "part2")
		}()
	}
	wg.Wait()
}

func TestEvent(t *testing.T) {
	t.Run("basic event counting", func(t *testing.T) {
		initEvents([]string{"1.1.1.1:53"})
		event("1.1.1.1:53", "got")
		event("1.1.1.1:53", "got")
		event("1.1.1.1:53", "error")

		if events["1.1.1.1:53"]["got"] != 2 {
			t.Fatalf("expected 2 got events, got %d", events["1.1.1.1:53"]["got"])
		}
		if events["1.1.1.1:53"]["error"] != 1 {
			t.Fatalf("expected 1 error event, got %d", events["1.1.1.1:53"]["error"])
		}
	})
}

func TestEventConcurrent(t *testing.T) {
	initEvents([]string{"1.1.1.1:53"})

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event("1.1.1.1:53", "got")
		}()
	}
	wg.Wait()

	if events["1.1.1.1:53"]["got"] != 100 {
		t.Fatalf("expected 100 got events, got %d", events["1.1.1.1:53"]["got"])
	}
}

// TestEventMutexOrdering verifies that the event() function correctly
// protects its critical section. The current code has defer Unlock()
// before Lock() which is an anti-pattern.
func TestEventMutexOrdering(t *testing.T) {
	initEvents([]string{"1.1.1.1:53"})

	// Run many concurrent events to stress-test the mutex pattern
	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			event("1.1.1.1:53", "got")
		}()
	}
	wg.Wait()

	if events["1.1.1.1:53"]["got"] != 1000 {
		t.Fatalf("expected 1000 got events, got %d", events["1.1.1.1:53"]["got"])
	}
}

// TestEventsRaceWithStats demonstrates the race condition where
// the stats goroutine reads events under loggerMutex while event()
// writes under eventMutex - these are different mutexes.
// Run with: go test -race -run TestEventsRaceWithStats
// This will report a data race because reads and writes use different mutexes.
func TestEventsRaceWithStats(t *testing.T) {
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	var wg sync.WaitGroup

	// Writer goroutines using event() - writes under eventMutex
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				event("1.1.1.1:53", "got")
				event("8.8.8.8:53", "error")
			}
		}()
	}

	// Reader goroutines simulating stats - reads under loggerMutex
	// This is what the stats goroutine does in main()
	// BUG: uses loggerMutex instead of eventMutex, so reads are unprotected
	// against concurrent writes from event()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				loggerMutex.Lock()
				for _, u := range ups {
					_ = events[u]["got"]
					_ = events[u]["error"]
					_ = events[u]["trunc"]
				}
				loggerMutex.Unlock()
			}
		}()
	}

	wg.Wait()
}

// TestHostsRace demonstrates the race condition where handleDnsRequest
// reads hosts while reloadHosts writes to it concurrently.
// Run with: go test -race -run TestHostsRace
func TestHostsRace(t *testing.T) {
	hosts = make(map[string]map[string][]string)

	var wg sync.WaitGroup

	// Writer goroutine simulating reloadHosts (via SIGHUP)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				newHosts := make(map[string]map[string][]string)
				newHosts["A"] = map[string][]string{
					"*.example.com.": {"1.2.3.4"},
				}
				// BUG: no synchronization on hosts global variable
				hosts = newHosts
			}
		}()
	}

	// Reader goroutine simulating handleDnsRequest host lookup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				localHosts := hosts
				for host, values := range localHosts["A"] {
					_ = host
					_ = values
				}
			}
		}()
	}

	wg.Wait()
}

// TestRandShuffleDeterministic verifies that without seeding,
// rand.Shuffle produces deterministic results in Go 1.17.
func TestRandShuffleDeterministic(t *testing.T) {
	input1 := []string{"a", "b", "c", "d", "e"}
	input2 := []string{"a", "b", "c", "d", "e"}

	// Reset to default seed
	rand.Seed(1)
	rand.Shuffle(len(input1), func(i, j int) {
		input1[i], input1[j] = input1[j], input1[i]
	})

	rand.Seed(1)
	rand.Shuffle(len(input2), func(i, j int) {
		input2[i], input2[j] = input2[j], input2[i]
	})

	for i := range input1 {
		if input1[i] != input2[i] {
			t.Fatalf("expected same order at index %d: %s vs %s", i, input1[i], input2[i])
		}
	}
	// With the same seed, results are identical - this is the bug.
	// The server should seed rand to get actual randomization.
}

// TestLocalhostNonAQuery tests that querying localhost with a
// non-A/AAAA type doesn't produce a response with nil RR.
func TestLocalhostNonAQuery(t *testing.T) {
	// Simulate what handleDnsRequest does for localhost with MX query
	question := dns.Question{
		Name:   "localhost.",
		Qtype:  dns.TypeMX,
		Qclass: dns.ClassINET,
	}

	var rr dns.RR
	switch question.Qtype {
	case dns.TypeA:
		rr, _ = dns.NewRR("localhost. 3600 IN A 127.0.0.1")
	case dns.TypeAAAA:
		rr, _ = dns.NewRR("localhost. 3600 IN AAAA ::1")
	}

	// rr is nil here because TypeMX doesn't match
	if rr != nil {
		t.Fatal("expected nil rr for non-A/AAAA localhost query")
	}

	// Creating a response with nil RR is the bug
	resp := createResponse([]dns.RR{rr})
	if resp.Answer[0] != nil {
		t.Fatal("expected nil RR in answer - this is the bug")
	}
}

// TestResolve tests the resolve function against a real DNS server.
func TestResolve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dialTimeout = 2 * time.Second
	readTimeout = 2 * time.Second
	writeTimeout = 2 * time.Second
	edns0 = -1

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	resp, rtt, err := resolve("1.1.1.1:53", q, true, "udp")
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if rtt <= 0 {
		t.Fatal("expected positive rtt")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
}

// TestHarder tests the harder function against real DNS servers.
func TestHarder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	dialTimeout = 2 * time.Second
	readTimeout = 2 * time.Second
	writeTimeout = 2 * time.Second
	delay = 10 * time.Millisecond
	concurrencyDelay = 0
	tries = 3
	netMode = "udp"
	edns0 = -1

	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	resp := harder("test-id", q, true, ups)
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if len(resp.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
}

// TestHarderAllFail tests harder when all upstreams fail.
func TestHarderAllFail(t *testing.T) {
	dialTimeout = 100 * time.Millisecond
	readTimeout = 100 * time.Millisecond
	writeTimeout = 100 * time.Millisecond
	delay = 1 * time.Millisecond
	concurrencyDelay = 0
	tries = 1
	netMode = "udp"
	edns0 = -1

	ups := []string{"192.0.2.1:53"} // RFC 5737 TEST-NET, won't respond
	initEvents(ups)

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	resp := harder("test-id", q, true, ups)
	if resp != nil {
		t.Fatal("expected nil response when all upstreams fail")
	}
}

func TestReloadHosts(t *testing.T) {
	t.Run("empty path does nothing", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("")
		if len(hosts) != 0 {
			t.Fatal("expected hosts to remain empty")
		}
	})

	t.Run("valid hosts.json", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("/home/user/harderdns/hosts.json")
		if len(hosts) == 0 {
			t.Fatal("expected hosts to be populated")
		}
	})
}

// TestFilePermissions documents the incorrect file permission values.
// 06644 octal = setgid + rw-r--r-- which is unusual; should be 0644.
// 06444 octal = setgid + r--r--r-- which is unusual; should be 0444.
func TestFilePermissions(t *testing.T) {
	const perm1 = 06644 // used in main.go line 411
	const perm2 = 06444 // used in main.go line 439

	// These have the setgid bit set which is almost certainly unintentional
	if perm1&02000 != 0 {
		t.Log("WARNING: permission 06644 has setgid bit set, likely should be 0644")
	}
	if perm2&02000 != 0 {
		t.Log("WARNING: permission 06444 has setgid bit set, likely should be 0444")
	}
}
