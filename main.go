package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

type HarderResult struct {
	records []dns.RR
	rtt     time.Duration
}

func resolve(upstream string, question dns.Question) HarderResult {
	c := dns.Client{
		Timeout: timeout,
	}
	m := dns.Msg{}

	var result HarderResult

	switch question.Qtype {
	case dns.TypeA:
		m.SetQuestion(question.Name, dns.TypeA)
		r, rtt, err := c.Exchange(&m, upstream)
		if err != nil {
			errors[upstream] = errors[upstream] + 1
			log.Println("ERROR", errors[upstream], "a", "c.Exchange", "err", err)
			break
		}
		result.rtt = rtt

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, ans.Header().Ttl, a.A.String()))
				if err != nil {
					log.Println("ERROR", "a", "dns.NewRR", err)
					continue
				}

				result.records = append(result.records, rr)
			}
		}
	case dns.TypeCNAME:
		m.SetQuestion(question.Name, dns.TypeA)
		r, rtt, err := c.Exchange(&m, upstream)
		if err != nil {
			errors[upstream] = errors[upstream] + 1
			log.Println("ERROR", errors[upstream], "cname", "c.Exchange", "err", err)
		}
		result.rtt = rtt

		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, ans.Header().Ttl, cname.String()))
				if err != nil {
					log.Println("ERROR", "cname", "dns.NewRR", err)
					continue
				}

				result.records = append(result.records, rr)
			}
		}
	}

	return result
}

func harder(question dns.Question, tries int) []dns.RR {
	try := 0
	var result HarderResult

	for try < tries {
		for _, upstream := range upstreams {
			result = resolve(upstream, question)

			if len(result.records) > 0 {
				log.Print("FOUND ", question.Name, " from ", upstream, " in ", result.rtt)
				return result.records
			}
		}

		try = try + 1
		log.Println("RETRY", question.Name, " after ", delay)
		time.Sleep(delay)
	}

	return result.records
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		records := harder(q, 3)
		m.Answer = append(m.Answer, records...)
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m)
	}

	if len(m.Answer) == 0 {
		log.Println("NXDOMAIN", r.Question[0].Name)
		m.SetRcode(r, dns.RcodeNameError)
	}

	w.WriteMsg(m)
}

var upstreams []string
var timeout time.Duration
var delay time.Duration

var errors map[string]int

func main() {
	timeoutMs := flag.Int("timeout", 101, "timeout in ms")
	delayMs := flag.Int("delay", 0, "delay in ms")

	flag.Parse()

	timeout = time.Millisecond * time.Duration(*timeoutMs)
	delay = time.Millisecond * time.Duration(*delayMs)

	upstreams = flag.Args()
	if len(upstreams) == 0 {
		log.Fatalln("no upstreams")
	}

	errors = make(map[string]int)
	for _, upstream := range upstreams {
		errors[upstream] = 0
	}

	dns.HandleFunc(".", handleDnsRequest)

	port := 53
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	defer server.Shutdown()

	log.Printf("Starting at :%d\n", port)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
