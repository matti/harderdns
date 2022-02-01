package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

func resolver(upstream string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, network, upstream)
		},
	}
}

func resolve(resolver *net.Resolver, question dns.Question) []dns.RR {
	var records []dns.RR
	ctx, _ := context.WithTimeout(context.Background(), timeout)

	switch question.Qtype {
	case dns.TypeA:
		ips, err := resolver.LookupIP(ctx, "ip4", question.Name)
		if err != nil {
			log.Println("r.LookupIPAddr", "err", err)
			return records
		}

		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN A %s", question.Name, ttl, ip.String()))
			if err != nil {
				log.Fatalln("a", "dns.NewRR", err)
			}
			records = append(records, rr)
		}
	case dns.TypeCNAME:
		name, err := resolver.LookupCNAME(ctx, question.Name)
		if err != nil {
			log.Println("r.LookupCNAME", "err", err)
			return records
		}
		record, err := dns.NewRR(fmt.Sprintf("%s %d CNAME %s", question.Name, ttl, name))
		if err != nil {
			log.Fatalln("cname", "dns.NewRR", err)
		}
		records = append(records, record)
	}

	return records
}

func harder(resolvers []*net.Resolver, question dns.Question, tries int) []dns.RR {
	try := 0
	var records []dns.RR

	for try < tries {
		log.Println("try", try)
		for _, resolver := range resolvers {
			records = append(records, resolve(resolver, question)...)

			if len(records) > 0 {
				log.Println("found", records)
				return records
			}
		}

		try = try + 1
	}

	return records
}

func parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		log.Println(q.String())
		records := harder(resolvers, q, 3)
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
		m.SetRcode(r, dns.RcodeNameError)
	}

	w.WriteMsg(m)
}

var resolvers []*net.Resolver
var timeout time.Duration
var ttl int

func main() {
	ttl = 20
	timeout = time.Millisecond * time.Duration(200)

	resolvers = append(resolvers, resolver("1.1.1.1:53"))
	resolvers = append(resolvers, resolver("8.8.8.8:53"))

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
