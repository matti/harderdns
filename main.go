package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

type HarderResult struct {
	records []dns.RR
	rtt     time.Duration
	error   bool
}

func resolve(id string, kind string, upstream string, question dns.Question) HarderResult {
	c := dns.Client{
		Timeout: timeout,
		Net:     net,
	}
	m := dns.Msg{}

	var result HarderResult
	result.error = false

	switch question.Qtype {
	case dns.TypeA:
		m.SetQuestion(question.Name, dns.TypeA)
		r, rtt, err := c.Exchange(&m, upstream)
		if err != nil {
			result.error = true
			errors[upstream] = errors[upstream] + 1
			log.Println(id, "ERROR ", kind, " ", upstream, errors[upstream], "A", "c.Exchange", "err", err)
			break
		}
		result.rtt = rtt

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.A); ok {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, ans.Header().Ttl, a.A.String()))
				if err != nil {
					log.Println(id, "ERROR", "A", "dns.NewRR", err)
					continue
				}

				result.records = append(result.records, rr)
			}
		}
	case dns.TypeAAAA:
		m.SetQuestion(question.Name, dns.TypeAAAA)
		r, rtt, err := c.Exchange(&m, upstream)
		if err != nil {
			result.error = true
			errors[upstream] = errors[upstream] + 1
			log.Println(id, "ERROR ", kind, " ", upstream, errors[upstream], "AAAA", "c.Exchange", "err", err)
			break
		}
		result.rtt = rtt

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.AAAA); ok {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", question.Name, ans.Header().Ttl, a.AAAA.String()))
				if err != nil {
					log.Println(id, "ERROR", "AAAA", "dns.NewRR", err)
					continue
				}

				result.records = append(result.records, rr)
			}
		}
	case dns.TypePTR:
		m.SetQuestion(question.Name, dns.TypePTR)
		r, rtt, err := c.Exchange(&m, upstream)
		if err != nil {
			result.error = true
			errors[upstream] = errors[upstream] + 1
			log.Println(id, "ERROR ", kind, " ", upstream, errors[upstream], "PTR", "c.Exchange", "err", err)
			break
		}
		result.rtt = rtt

		for _, ans := range r.Answer {
			if a, ok := ans.(*dns.PTR); ok {
				rr, err := dns.NewRR(fmt.Sprintf("%s %d IN PTR %s\n", question.Name, ans.Header().Ttl, a.Ptr))
				if err != nil {
					log.Println(id, "ERROR", "PTR", "dns.NewRR", err)
					continue
				}

				result.records = append(result.records, rr)
			}
		}
	default:
		log.Println("SKIP", question.String())
	}

	return result
}

func harder(kind string, id string, question dns.Question) []dns.RR {
	try := 0
	var result HarderResult

	log.Println(id, "ASK   ", kind, " ", question.Name)

	for try < tries {
		for _, upstream := range upstreams {
			result = resolve(id, kind, upstream, question)

			if len(result.records) > 0 {
				log.Println(id, "FOUND ", kind, " ", question.Name, "from", upstream, "in", result.rtt)
				return result.records
			}

			if !retry && !result.error {
				return result.records
			}
		}

		try = try + 1
		log.Println(id, "RETRY ", kind, " ", question.Name, "after", delay, "try", try)
		time.Sleep(delay)
	}

	return result.records
}

func parseQuery(kind string, id string, m *dns.Msg) {
	for _, q := range m.Question {
		if q.Name == "localhost." {
			var rr dns.RR
			switch q.Qtype {
			case dns.TypeA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", q.Name, 3600, "127.0.0.1"))
			case dns.TypeAAAA:
				rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", q.Name, 3600, "::1"))
			}

			m.Answer = append(m.Answer, rr)
		} else {
			records := harder(kind, id, q)
			m.Answer = append(m.Answer, records...)
		}
	}
}

func handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	var kind string
	id := uuid.New().String()

	switch m.Question[0].Qtype {
	case dns.TypeA:
		kind = "A   "
	case dns.TypeAAAA:
		kind = "AAAA"
	case dns.TypePTR:
		kind = "PTR"
	default:
		log.Println(id, "IGNORE", m.Question[len(m.Question)-1].String())

		w.WriteMsg(m)
		return
	}

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(kind, id, m)
	}

	if len(m.Answer) == 0 {
		log.Println(id, "NXDOM ", kind, " ", r.Question[0].Name)
		m.SetRcode(r, dns.RcodeNameError)
	}

	w.WriteMsg(m)
}

var upstreams []string
var timeout time.Duration
var delay time.Duration
var tries int
var retry bool
var net string

var errors map[string]int

func main() {
	timeoutMs := flag.Int("timeout", 500, "timeout in ms")
	delayMs := flag.Int("delay", 10, "delay in ms")
	flag.IntVar(&tries, "tries", 3, "tries")
	flag.BoolVar(&retry, "retry", false, "retry")
	flag.StringVar(&net, "net", "udp", "udp, tcp, tcp-tls")
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

	log.Printf("Starting at :%d using %s\n", port, net)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
