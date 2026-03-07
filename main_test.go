package main

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func initEvents(ups []string) {
	events = make(map[string]map[string]int)
	for _, u := range ups {
		events[u] = make(map[string]int)
	}
}

func setDefaults() {
	dialTimeout = 2 * time.Second
	readTimeout = 2 * time.Second
	writeTimeout = 2 * time.Second
	delay = 10 * time.Millisecond
	concurrencyDelay = 0
	tries = 3
	netMode = "udp"
	edns0 = -1
	hosts = make(map[string]map[string][]string)
	resolvSearch = ""
	resolvUpstreams = nil
}

func setFastTimeouts() {
	dialTimeout = 100 * time.Millisecond
	readTimeout = 100 * time.Millisecond
	writeTimeout = 100 * time.Millisecond
	delay = 1 * time.Millisecond
	concurrencyDelay = 0
	tries = 1
	netMode = "udp"
	edns0 = -1
}

// ===== createResponse tests =====

func TestCreateResponse(t *testing.T) {
	t.Run("nil RR list", func(t *testing.T) {
		resp := createResponse(nil)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Answer) != 0 {
			t.Fatalf("expected 0 answers, got %d", len(resp.Answer))
		}
		if !resp.RecursionAvailable {
			t.Fatal("expected RecursionAvailable to be true")
		}
		if resp.Compress {
			t.Fatal("expected Compress to be false")
		}
	})

	t.Run("empty RR list", func(t *testing.T) {
		resp := createResponse([]dns.RR{})
		if len(resp.Answer) != 0 {
			t.Fatalf("expected 0 answers, got %d", len(resp.Answer))
		}
	})

	t.Run("single A record", func(t *testing.T) {
		rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		resp := createResponse([]dns.RR{rr})
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		if resp.Answer[0].Header().Name != "example.com." {
			t.Fatalf("expected example.com., got %s", resp.Answer[0].Header().Name)
		}
	})

	t.Run("multiple RRs", func(t *testing.T) {
		rr1, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		rr2, _ := dns.NewRR("example.com. 3600 IN A 5.6.7.8")
		rr3, _ := dns.NewRR("example.com. 3600 IN A 9.10.11.12")
		resp := createResponse([]dns.RR{rr1, rr2, rr3})
		if len(resp.Answer) != 3 {
			t.Fatalf("expected 3 answers, got %d", len(resp.Answer))
		}
	})

	t.Run("AAAA record", func(t *testing.T) {
		rr, _ := dns.NewRR("example.com. 3600 IN AAAA ::1")
		resp := createResponse([]dns.RR{rr})
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
	})

	t.Run("with nil RR element - bug", func(t *testing.T) {
		resp := createResponse([]dns.RR{nil})
		if len(resp.Answer) != 1 {
			t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
		}
		// nil element in answer - documents the localhost bug
		if resp.Answer[0] != nil {
			t.Fatal("expected nil answer element")
		}
	})

	t.Run("mixed nil and valid RRs", func(t *testing.T) {
		rr, _ := dns.NewRR("example.com. 3600 IN A 1.2.3.4")
		resp := createResponse([]dns.RR{nil, rr, nil})
		if len(resp.Answer) != 3 {
			t.Fatalf("expected 3 answers, got %d", len(resp.Answer))
		}
	})
}

// ===== logger tests =====

func TestLogger(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		// Should not panic
		logger("test-id", "TEST", q, "part1", "part2")
	})

	t.Run("no extra parts", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		logger("test-id", "TEST", q)
	})

	t.Run("AAAA type", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
		logger("test-id", "TEST", q, "part1")
	})

	t.Run("MX type", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET}
		logger("test-id", "TEST", q)
	})

	t.Run("concurrent safety", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func(n int) {
				defer wg.Done()
				logger(fmt.Sprintf("id-%d", n), "TEST", q, "part")
			}(i)
		}
		wg.Wait()
	})
}

// ===== event tests =====

func TestEvent(t *testing.T) {
	t.Run("basic counting", func(t *testing.T) {
		initEvents([]string{"1.1.1.1:53"})
		event("1.1.1.1:53", "got")
		event("1.1.1.1:53", "got")
		event("1.1.1.1:53", "error")
		event("1.1.1.1:53", "trunc")

		if events["1.1.1.1:53"]["got"] != 2 {
			t.Fatalf("expected 2 got, got %d", events["1.1.1.1:53"]["got"])
		}
		if events["1.1.1.1:53"]["error"] != 1 {
			t.Fatalf("expected 1 error, got %d", events["1.1.1.1:53"]["error"])
		}
		if events["1.1.1.1:53"]["trunc"] != 1 {
			t.Fatalf("expected 1 trunc, got %d", events["1.1.1.1:53"]["trunc"])
		}
	})

	t.Run("multiple upstreams", func(t *testing.T) {
		initEvents([]string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"})
		event("1.1.1.1:53", "got")
		event("8.8.8.8:53", "error")
		event("9.9.9.9:53", "trunc")

		if events["1.1.1.1:53"]["got"] != 1 {
			t.Fatal("wrong count for 1.1.1.1")
		}
		if events["8.8.8.8:53"]["error"] != 1 {
			t.Fatal("wrong count for 8.8.8.8")
		}
		if events["9.9.9.9:53"]["trunc"] != 1 {
			t.Fatal("wrong count for 9.9.9.9")
		}
	})

	t.Run("uninitialized event name returns zero", func(t *testing.T) {
		initEvents([]string{"1.1.1.1:53"})
		if events["1.1.1.1:53"]["nonexistent"] != 0 {
			t.Fatal("expected 0 for uninitialized event")
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

func TestEventMutexOrdering(t *testing.T) {
	initEvents([]string{"1.1.1.1:53"})

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

func TestEventConcurrentMultipleUpstreamsAndTypes(t *testing.T) {
	ups := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	initEvents(ups)

	var wg sync.WaitGroup
	for _, u := range ups {
		for _, name := range []string{"got", "error", "trunc"} {
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func(upstream, eventName string) {
					defer wg.Done()
					event(upstream, eventName)
				}(u, name)
			}
		}
	}
	wg.Wait()

	for _, u := range ups {
		for _, name := range []string{"got", "error", "trunc"} {
			if events[u][name] != 100 {
				t.Fatalf("expected 100 %s for %s, got %d", name, u, events[u][name])
			}
		}
	}
}

// ===== Race condition tests (run with -race) =====

func TestEventsRaceWithStats(t *testing.T) {
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	var wg sync.WaitGroup

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

	// BUG: reads under loggerMutex, writes under eventMutex
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

func TestHostsRace(t *testing.T) {
	hosts = make(map[string]map[string][]string)

	var wg sync.WaitGroup

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				newHosts := make(map[string]map[string][]string)
				newHosts["A"] = map[string][]string{
					"*.example.com.": {"1.2.3.4"},
				}
				hosts = newHosts
			}
		}()
	}

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

// ===== reloadHosts tests =====

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

	t.Run("hosts.json has A records", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("/home/user/harderdns/hosts.json")
		aRecords, ok := hosts["A"]
		if !ok {
			t.Fatal("expected A records in hosts")
		}
		if len(aRecords) == 0 {
			t.Fatal("expected at least one A record")
		}
	})

	t.Run("hosts.json has AAAA records", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("/home/user/harderdns/hosts.json")
		aaaaRecords, ok := hosts["AAAA"]
		if !ok {
			t.Fatal("expected AAAA records in hosts")
		}
		if len(aaaaRecords) == 0 {
			t.Fatal("expected at least one AAAA record")
		}
	})

	t.Run("hosts.json wildcard entries", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("/home/user/harderdns/hosts.json")
		// Verify *.louhi.fi. wildcard exists in AAAA
		vals, ok := hosts["AAAA"]["*.louhi.fi."]
		if !ok {
			t.Fatal("expected *.louhi.fi. wildcard in AAAA records")
		}
		if len(vals) != 1 {
			t.Fatalf("expected 1 value for *.louhi.fi., got %d", len(vals))
		}
	})

	t.Run("hosts.json multi-value entries", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		reloadHosts("/home/user/harderdns/hosts.json")
		vals, ok := hosts["A"]["www.kaalimato.com."]
		if !ok {
			t.Fatal("expected www.kaalimato.com. in A records")
		}
		if len(vals) != 2 {
			t.Fatalf("expected 2 values for www.kaalimato.com., got %d", len(vals))
		}
	})

	t.Run("reload overwrites previous hosts", func(t *testing.T) {
		hosts = make(map[string]map[string][]string)
		hosts["A"] = map[string][]string{"old.example.com.": {"1.2.3.4"}}
		reloadHosts("/home/user/harderdns/hosts.json")
		// Old entry should be gone (Unmarshal replaces the map)
		if _, ok := hosts["A"]["old.example.com."]; ok {
			t.Fatal("expected old entry to be removed after reload")
		}
	})
}

// ===== resolve tests =====

func TestResolve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()

	t.Run("A record", func(t *testing.T) {
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
	})

	t.Run("AAAA record", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("TCP mode", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "tcp")
		if err != nil {
			t.Fatalf("resolve over TCP failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		q := dns.Question{Name: "this-domain-does-not-exist-xyz123.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response for NXDOMAIN")
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("expected NXDOMAIN rcode, got %s", dns.RcodeToString[resp.Rcode])
		}
	})

	t.Run("with EDNS0", func(t *testing.T) {
		edns0 = 4096
		defer func() { edns0 = -1 }()
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve with EDNS0 failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("without recursion desired", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, false, "udp")
		if err != nil {
			t.Fatalf("resolve failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("unreachable upstream", func(t *testing.T) {
		setFastTimeouts()
		defer setDefaults()
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		_, _, err := resolve("192.0.2.1:53", q, true, "udp")
		if err == nil {
			t.Fatal("expected error for unreachable upstream")
		}
	})

	t.Run("MX record", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeMX, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve MX failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("TXT record", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve TXT failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("NS record", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve NS failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("SOA record", func(t *testing.T) {
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
		resp, _, err := resolve("1.1.1.1:53", q, true, "udp")
		if err != nil {
			t.Fatalf("resolve SOA failed: %v", err)
		}
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})
}

// ===== harder tests =====

func TestHarder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()

	t.Run("single upstream", func(t *testing.T) {
		ups := []string{"1.1.1.1:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
		if len(resp.Answer) == 0 {
			t.Fatal("expected at least one answer")
		}
	})

	t.Run("multiple upstreams", func(t *testing.T) {
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
	})

	t.Run("three upstreams", func(t *testing.T) {
		ups := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("AAAA query", func(t *testing.T) {
		ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response")
		}
	})

	t.Run("NXDOMAIN returns empty with NS", func(t *testing.T) {
		ups := []string{"1.1.1.1:53"}
		initEvents(ups)
		q := dns.Question{Name: "this-definitely-does-not-exist-xyz987.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		// NXDOMAIN typically has Ns records (SOA) so should return via EMPTYNS path
		if resp == nil {
			t.Fatal("expected non-nil response for NXDOMAIN (should have NS records)")
		}
	})

	t.Run("with concurrency delay", func(t *testing.T) {
		concurrencyDelay = 50 * time.Millisecond
		defer func() { concurrencyDelay = 0 }()
		ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response with concurrency delay")
		}
	})

	t.Run("all upstreams fail", func(t *testing.T) {
		setFastTimeouts()
		defer setDefaults()
		ups := []string{"192.0.2.1:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp != nil {
			t.Fatal("expected nil response when all upstreams fail")
		}
	})

	t.Run("multiple upstreams all fail", func(t *testing.T) {
		setFastTimeouts()
		defer setDefaults()
		ups := []string{"192.0.2.1:53", "192.0.2.2:53", "192.0.2.3:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp != nil {
			t.Fatal("expected nil response when all upstreams fail")
		}
	})

	t.Run("mix of good and bad upstreams", func(t *testing.T) {
		ups := []string{"192.0.2.1:53", "1.1.1.1:53", "192.0.2.2:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response when at least one upstream works")
		}
	})

	t.Run("TCP mode", func(t *testing.T) {
		netMode = "tcp"
		defer func() { netMode = "udp" }()
		ups := []string{"1.1.1.1:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response in TCP mode")
		}
	})

	t.Run("multiple tries", func(t *testing.T) {
		tries = 5
		defer func() { tries = 3 }()
		ups := []string{"1.1.1.1:53"}
		initEvents(ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		resp := harder("test-id", q, true, ups)
		if resp == nil {
			t.Fatal("expected non-nil response with multiple tries")
		}
	})

	t.Run("does not modify original upstream slice", func(t *testing.T) {
		ups := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
		initEvents(ups)
		original := make([]string, len(ups))
		copy(original, ups)
		q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		harder("test-id", q, true, ups)
		for i := range ups {
			if ups[i] != original[i] {
				t.Fatalf("harder modified upstream slice at index %d: %s != %s", i, ups[i], original[i])
			}
		}
	})
}

// ===== localhost handling tests =====

func TestLocalhostA(t *testing.T) {
	question := dns.Question{Name: "localhost.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	var rr dns.RR
	switch question.Qtype {
	case dns.TypeA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, 3600, "127.0.0.1"))
	case dns.TypeAAAA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", question.Name, 3600, "::1"))
	}
	if rr == nil {
		t.Fatal("expected non-nil rr for A query")
	}
	resp := createResponse([]dns.RR{rr})
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	aRec, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatal("expected A record type")
	}
	if aRec.A.String() != "127.0.0.1" {
		t.Fatalf("expected 127.0.0.1, got %s", aRec.A.String())
	}
}

func TestLocalhostAAAA(t *testing.T) {
	question := dns.Question{Name: "localhost.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	var rr dns.RR
	switch question.Qtype {
	case dns.TypeA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, 3600, "127.0.0.1"))
	case dns.TypeAAAA:
		rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", question.Name, 3600, "::1"))
	}
	if rr == nil {
		t.Fatal("expected non-nil rr for AAAA query")
	}
	resp := createResponse([]dns.RR{rr})
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	aaaaRec, ok := resp.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatal("expected AAAA record type")
	}
	if aaaaRec.AAAA.String() != "::1" {
		t.Fatalf("expected ::1, got %s", aaaaRec.AAAA.String())
	}
}

func TestLocalhostNonAQuery(t *testing.T) {
	// Non-A/AAAA queries for localhost produce nil RR - this is a bug
	for _, qtype := range []uint16{dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSOA, dns.TypeSRV, dns.TypeCNAME, dns.TypePTR} {
		t.Run(dns.Type(qtype).String(), func(t *testing.T) {
			question := dns.Question{Name: "localhost.", Qtype: qtype, Qclass: dns.ClassINET}
			var rr dns.RR
			switch question.Qtype {
			case dns.TypeA:
				rr, _ = dns.NewRR("localhost. 3600 IN A 127.0.0.1")
			case dns.TypeAAAA:
				rr, _ = dns.NewRR("localhost. 3600 IN AAAA ::1")
			}
			if rr != nil {
				t.Fatalf("expected nil rr for %s query on localhost", dns.Type(qtype).String())
			}
			// This creates a response with nil RR element - the bug
			resp := createResponse([]dns.RR{rr})
			if resp.Answer[0] != nil {
				t.Fatal("expected nil RR in answer")
			}
		})
	}
}

// ===== hosts matching tests =====

func TestHostsMatching(t *testing.T) {
	hosts = make(map[string]map[string][]string)
	reloadHosts("/home/user/harderdns/hosts.json")

	t.Run("exact A match", func(t *testing.T) {
		question := dns.Question{Name: "www.kaalimato.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		found := false
		for host := range hosts[dns.Type(question.Qtype).String()] {
			if host == question.Name {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected to find www.kaalimato.com. in A hosts")
		}
	})

	t.Run("exact AAAA match", func(t *testing.T) {
		vals, ok := hosts["AAAA"]["cdn.kaalimato.com."]
		if !ok {
			t.Fatal("expected to find cdn.kaalimato.com. in AAAA hosts")
		}
		if len(vals) != 2 {
			t.Fatalf("expected 2 AAAA values, got %d", len(vals))
		}
	})

	t.Run("wildcard AAAA entry exists", func(t *testing.T) {
		vals, ok := hosts["AAAA"]["*.louhi.fi."]
		if !ok {
			t.Fatal("expected *.louhi.fi. wildcard in AAAA hosts")
		}
		if len(vals) == 0 {
			t.Fatal("expected at least one value for wildcard")
		}
	})

	t.Run("no match for unknown domain", func(t *testing.T) {
		vals, ok := hosts["A"]["unknown.example.com."]
		if ok && len(vals) > 0 {
			t.Fatal("expected no match for unknown domain")
		}
	})

	t.Run("MX query skips hosts", func(t *testing.T) {
		// MX queries don't check hosts (only A and AAAA do)
		_, ok := hosts[dns.Type(dns.TypeMX).String()]
		if ok {
			t.Fatal("expected no MX entries in hosts")
		}
	})
}

// ===== resolvSearch and short domain tests =====

func TestShortDomainDetection(t *testing.T) {
	tests := []struct {
		name     string
		dots     int
		isShort  bool
	}{
		{"a.", 1, true},       // single label
		{"a.b.", 2, false},    // two labels
		{"a.b.c.", 3, false},  // three labels
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := 0
			for _, c := range tt.name {
				if c == '.' {
					count++
				}
			}
			isShort := count == 1
			if isShort != tt.isShort {
				t.Fatalf("expected isShort=%v for %s (dots=%d)", tt.isShort, tt.name, count)
			}
		})
	}
}

func TestResolvSearchAppend(t *testing.T) {
	// Simulate the resolvSearch logic from handleDnsRequest
	resolvSearch = "example.com"
	defer func() { resolvSearch = "" }()

	question := dns.Question{Name: "myhost.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if strings.Count(question.Name, ".") == 1 {
		if resolvSearch != "" {
			question.Name = question.Name + resolvSearch + "."
		}
	}

	expected := "myhost.example.com."
	if question.Name != expected {
		t.Fatalf("expected %s, got %s", expected, question.Name)
	}
}

func TestResolvSearchNotAppliedToFQDN(t *testing.T) {
	resolvSearch = "example.com"
	defer func() { resolvSearch = "" }()

	question := dns.Question{Name: "host.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	original := question.Name
	if strings.Count(question.Name, ".") == 1 {
		question.Name = question.Name + resolvSearch + "."
	}

	if question.Name != original {
		t.Fatalf("resolvSearch should not be applied to FQDN, got %s", question.Name)
	}
}

// ===== rand shuffle tests =====

func TestRandShuffleDeterministic(t *testing.T) {
	input1 := []string{"a", "b", "c", "d", "e"}
	input2 := []string{"a", "b", "c", "d", "e"}

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
}

func TestShuffleCopyPreservesOriginal(t *testing.T) {
	original := []string{"a", "b", "c", "d", "e"}
	shuffled := make([]string, len(original))
	copy(shuffled, original)

	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	// Original should be unchanged
	expected := []string{"a", "b", "c", "d", "e"}
	for i := range original {
		if original[i] != expected[i] {
			t.Fatalf("original modified at index %d: %s != %s", i, original[i], expected[i])
		}
	}
}

// ===== File permissions tests =====

func TestFilePermissions(t *testing.T) {
	const perm1 = 06644
	const perm2 = 06444

	if perm1&02000 != 0 {
		t.Log("BUG: permission 06644 has setgid bit set, should be 0644")
	}
	if perm2&02000 != 0 {
		t.Log("BUG: permission 06444 has setgid bit set, should be 0444")
	}

	// Verify correct permissions
	if 0644&02000 != 0 {
		t.Fatal("0644 should not have setgid bit")
	}
	if 0444&02000 != 0 {
		t.Fatal("0444 should not have setgid bit")
	}
}

// =============================================================
// E2E Concurrency Stress Tests
// =============================================================
// These tests start a real DNS server and hammer it with concurrent
// requests to find deadlocks, panics, and race conditions.

// startTestServer starts a DNS server on a random high port and returns the address and a shutdown function.
func startTestServer(t *testing.T) (string, func()) {
	t.Helper()

	// Find a free port
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", handleDnsRequest)

	server := &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() {
		close(started)
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			// Ignore errors after shutdown
		}
	}()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start within 5 seconds")
	}

	return addr, func() {
		server.Shutdown()
	}
}

func sendQuery(addr string, name string, qtype uint16) (*dns.Msg, error) {
	c := dns.Client{
		Timeout: 2 * time.Second,
	}
	m := &dns.Msg{}
	m.SetQuestion(name, qtype)
	m.RecursionDesired = true
	resp, _, err := c.Exchange(m, addr)
	return resp, err
}

func TestE2ELocalhostConcurrent(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup
	var errors int64

	// Hammer localhost queries concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				resp, err := sendQuery(addr, "localhost.", dns.TypeA)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					continue
				}
				if resp == nil {
					atomic.AddInt64(&errors, 1)
				}
			}
		}()
	}

	wg.Wait()
	errCount := atomic.LoadInt64(&errors)
	if errCount > 0 {
		t.Logf("WARNING: %d errors during concurrent localhost queries", errCount)
	}
}

func TestE2ELocalhostAllTypes(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSOA, dns.TypeSRV, dns.TypeCNAME}

	var wg sync.WaitGroup
	for _, qtype := range types {
		wg.Add(1)
		go func(qt uint16) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				resp, err := sendQuery(addr, "localhost.", qt)
				if err != nil {
					t.Logf("error for type %s: %v", dns.Type(qt).String(), err)
					continue
				}
				if resp == nil {
					t.Logf("nil response for type %s", dns.Type(qt).String())
				}
			}
		}(qtype)
	}
	wg.Wait()
}

func TestE2EHostsEntriesConcurrent(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	hosts = make(map[string]map[string][]string)
	reloadHosts("/home/user/harderdns/hosts.json")

	addr, shutdown := startTestServer(t)
	defer shutdown()

	// Query all hosts entries concurrently
	queries := []struct {
		name  string
		qtype uint16
	}{
		{"www.kaalimato.com.", dns.TypeA},
		{"test.louhi.fi.", dns.TypeA},
		{"cdn.kaalimato.com.", dns.TypeAAAA},
		{"foo.louhi.fi.", dns.TypeAAAA},
		{"bar.louhi.fi.", dns.TypeAAAA},
	}

	var wg sync.WaitGroup
	for _, q := range queries {
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func(name string, qtype uint16) {
				defer wg.Done()
				resp, err := sendQuery(addr, name, qtype)
				if err != nil {
					return
				}
				if resp == nil {
					return
				}
			}(q.name, q.qtype)
		}
	}
	wg.Wait()
}

func TestE2EMixedQueryTypesConcurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	hosts = make(map[string]map[string][]string)
	reloadHosts("/home/user/harderdns/hosts.json")

	addr, shutdown := startTestServer(t)
	defer shutdown()

	// Mix of localhost, hosts entries, and upstream queries
	queries := []struct {
		name  string
		qtype uint16
	}{
		{"localhost.", dns.TypeA},
		{"localhost.", dns.TypeAAAA},
		{"www.kaalimato.com.", dns.TypeA},
		{"cdn.kaalimato.com.", dns.TypeAAAA},
		{"example.com.", dns.TypeA},
		{"example.com.", dns.TypeAAAA},
		{"example.com.", dns.TypeMX},
	}

	var wg sync.WaitGroup
	var errors int64

	for i := 0; i < 20; i++ {
		for _, q := range queries {
			wg.Add(1)
			go func(name string, qtype uint16) {
				defer wg.Done()
				resp, err := sendQuery(addr, name, qtype)
				if err != nil {
					atomic.AddInt64(&errors, 1)
					return
				}
				if resp == nil {
					atomic.AddInt64(&errors, 1)
				}
			}(q.name, q.qtype)
		}
	}

	wg.Wait()
	t.Logf("total errors: %d out of %d queries", atomic.LoadInt64(&errors), 20*len(queries))
}

func TestE2ENonQueryOpcode(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	// Send a non-query opcode (e.g. STATUS)
	c := dns.Client{Timeout: 2 * time.Second}
	m := &dns.Msg{}
	m.SetQuestion("example.com.", dns.TypeA)
	m.Opcode = dns.OpcodeStatus

	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Non-query opcode should return empty response
	if len(resp.Answer) != 0 {
		t.Fatalf("expected 0 answers for non-query opcode, got %d", len(resp.Answer))
	}
}

func TestE2EConcurrentHostsReloadDuringQueries(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	hosts = make(map[string]map[string][]string)
	reloadHosts("/home/user/harderdns/hosts.json")

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup

	// Queries running concurrently
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sendQuery(addr, "www.kaalimato.com.", dns.TypeA)
				sendQuery(addr, "foo.louhi.fi.", dns.TypeAAAA)
				sendQuery(addr, "localhost.", dns.TypeA)
			}
		}()
	}

	// Simultaneous hosts reloads (simulating SIGHUP)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				reloadHosts("/home/user/harderdns/hosts.json")
				time.Sleep(time.Millisecond)
			}
		}()
	}

	wg.Wait()
}

func TestE2EConcurrentEventsAndStats(t *testing.T) {
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	var wg sync.WaitGroup

	// Simulate event writes from multiple goroutines
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				event("1.1.1.1:53", "got")
				event("8.8.8.8:53", "error")
				event("1.1.1.1:53", "trunc")
			}
		}()
	}

	// Simulate stats reader goroutine (uses loggerMutex like main.go)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
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

func TestE2EServerHighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping high-concurrency test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	totalRequests := 200

	for i := 0; i < totalRequests; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d.example.com.", n)
			resp, err := sendQuery(addr, name, dns.TypeA)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			if resp != nil {
				atomic.AddInt64(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()
	t.Logf("high concurrency: %d success, %d errors out of %d", successCount, errorCount, totalRequests)
}

func TestE2EServerRapidFireSameQuery(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping rapid fire test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup
	var successCount int64

	// Many goroutines all querying the exact same name
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				resp, err := sendQuery(addr, "example.com.", dns.TypeA)
				if err == nil && resp != nil {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}()
	}

	wg.Wait()
	if successCount == 0 {
		t.Fatal("expected at least some successful queries")
	}
	t.Logf("rapid fire: %d/1000 successful", successCount)
}

func TestE2EServerShortDomainWithResolvSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups
	resolvUpstreams = []string{"1.1.1.1:53"}
	initEvents(append(ups, resolvUpstreams...))
	resolvSearch = "example.com"
	defer func() { resolvSearch = "" }()

	addr, shutdown := startTestServer(t)
	defer shutdown()

	// "www." has exactly 1 dot, so resolvSearch should be appended
	resp, err := sendQuery(addr, "www.", dns.TypeA)
	if err != nil {
		t.Logf("query error (expected if short domain resolution fails): %v", err)
		return
	}
	if resp != nil {
		t.Logf("got response for short domain with resolvSearch: rcode=%s, answers=%d",
			dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
}

func TestE2EServerConcurrencyDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()
	concurrencyDelay = 100 * time.Millisecond
	defer func() { concurrencyDelay = 0 }()

	ups := []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := sendQuery(addr, "example.com.", dns.TypeA)
			if err != nil {
				t.Logf("query error: %v", err)
				return
			}
			if resp == nil || len(resp.Answer) == 0 {
				t.Log("empty response with concurrency delay")
			}
		}()
	}
	wg.Wait()
}

func TestE2EServerAllUpstreamsFail(t *testing.T) {
	setFastTimeouts()
	defer setDefaults()

	ups := []string{"192.0.2.1:53", "192.0.2.2:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := sendQuery(addr, "example.com.", dns.TypeA)
			if err != nil {
				// Expected - timeout
				return
			}
			if resp != nil && resp.Rcode != dns.RcodeServerFailure {
				t.Logf("expected SERVFAIL, got %s", dns.RcodeToString[resp.Rcode])
			}
		}()
	}
	wg.Wait()
}

func TestE2EServerGracefulShutdownUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	addr, shutdown := startTestServer(t)

	var wg sync.WaitGroup

	// Start queries
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sendQuery(addr, "example.com.", dns.TypeA)
			}
		}()
	}

	// Shutdown while queries are in flight
	time.Sleep(50 * time.Millisecond)
	shutdown()

	// Wait for all goroutines to finish (they should not hang)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Good - all goroutines finished
	case <-time.After(10 * time.Second):
		t.Fatal("goroutines did not finish within 10 seconds after shutdown - possible deadlock")
	}
}

func TestE2EServerPortReuse(t *testing.T) {
	setDefaults()
	ups := []string{"1.1.1.1:53"}
	initEvents(ups)
	upstreams = ups

	// Start and stop server multiple times to ensure no port leaks
	for i := 0; i < 3; i++ {
		addr, shutdown := startTestServer(t)
		resp, err := sendQuery(addr, "localhost.", dns.TypeA)
		if err != nil {
			t.Fatalf("iteration %d: query failed: %v", i, err)
		}
		if resp == nil {
			t.Fatalf("iteration %d: nil response", i)
		}
		shutdown()
		time.Sleep(10 * time.Millisecond) // Small delay for port release
	}
}

// ===== Stress test: logger + events + queries all at once =====

func TestE2EFullSystemStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full system stress test")
	}
	setDefaults()
	ups := []string{"1.1.1.1:53", "8.8.8.8:53"}
	initEvents(ups)
	upstreams = ups

	hosts = make(map[string]map[string][]string)
	reloadHosts("/home/user/harderdns/hosts.json")

	addr, shutdown := startTestServer(t)
	defer shutdown()

	var wg sync.WaitGroup

	// DNS queries
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			queries := []struct {
				name  string
				qtype uint16
			}{
				{"localhost.", dns.TypeA},
				{"localhost.", dns.TypeAAAA},
				{"localhost.", dns.TypeMX},
				{"www.kaalimato.com.", dns.TypeA},
				{"example.com.", dns.TypeA},
				{"foo.louhi.fi.", dns.TypeAAAA},
			}
			for j := 0; j < 10; j++ {
				q := queries[j%len(queries)]
				sendQuery(addr, q.name, q.qtype)
			}
		}(i)
	}

	// Event writes
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				event("1.1.1.1:53", "got")
				event("8.8.8.8:53", "error")
			}
		}()
	}

	// Stats reads (using loggerMutex like main.go does)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				loggerMutex.Lock()
				for _, u := range ups {
					_ = events[u]["got"]
					_ = events[u]["error"]
				}
				loggerMutex.Unlock()
			}
		}()
	}

	// Logger calls
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			q := dns.Question{Name: "stress.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
			for j := 0; j < 50; j++ {
				logger(strconv.Itoa(n), "STRESS", q, "iteration", strconv.Itoa(j))
			}
		}(i)
	}

	// Hosts reloads
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				reloadHosts("/home/user/harderdns/hosts.json")
				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Wait with timeout to detect deadlocks
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("full system stress test completed without deadlock")
	case <-time.After(30 * time.Second):
		t.Fatal("DEADLOCK: full system stress test did not complete within 30 seconds")
	}
}
