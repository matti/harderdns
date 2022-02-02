package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

func resolve(upstream string, question dns.Question) (*dns.Msg, time.Duration, error) {
	c := dns.Client{
		Timeout: timeout,
		Net:     net,
	}

	query := &dns.Msg{}
	query.SetQuestion(question.Name, question.Qtype)

	return c.Exchange(query, upstream)
}

func harder(id string, question dns.Question) *dns.Msg {
	try := 0

	for try < tries {
		for _, upstream := range upstreams {
			response, rtt, err := resolve(upstream, question)
			if err == nil {
				return response
			} else {
				logger(id, "ERROR", question, fmt.Sprintf("%v", err)+" "+rtt.String())
			}
		}

		try = try + 1
		logger(id, "RETRY", question, strconv.Itoa(try))
		time.Sleep(delay)
	}

	return nil
}

func logger(id string, kind string, question dns.Question, parts ...string) {
	var sb strings.Builder

	sb.WriteString(id)
	sb.WriteString("\t")
	sb.WriteString(kind)
	sb.WriteString("\t")
	sb.WriteString(dns.Type(question.Qtype).String())
	sb.WriteString("\t")
	sb.WriteString(question.Name)
	sb.WriteString(" ")

	for _, part := range parts {
		sb.WriteString(part)
		sb.WriteString("\t")
	}

	println(sb.String())
}

func handleDnsRequest(w dns.ResponseWriter, request *dns.Msg) {
	id := uuid.New().String()

	final := new(dns.Msg)
	final.SetReply(request)
	final.Compress = false
	final.RecursionAvailable = true

	if request.Opcode != dns.OpcodeQuery {
		w.WriteMsg(final)
		return
	}

	// https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
	question := request.Question[0]

	logger(id, "QUERY", question)

	switch question.Name {
	case "localhost.":
		switch question.Qtype {
		case dns.TypeA:
			rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, 3600, "127.0.0.1"))
			final.Answer = append(final.Answer, rr)
		case dns.TypeAAAA:
			rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", question.Name, 3600, "::1"))
			final.Answer = append(final.Answer, rr)
		}
	default:
		response := harder(id, question)
		if response != nil {
			final.Answer = response.Answer
			final.Ns = response.Ns
			final.Extra = response.Extra
			final.SetRcode(request, response.Rcode)
		} else {
			final.SetRcode(request, dns.RcodeServerFailure)
		}
	}
	answers := strconv.Itoa(len(final.Answer))
	nss := strconv.Itoa(len(final.Ns))
	extras := strconv.Itoa(len(final.Extra))

	logger(id, "ANSWER", question, dns.RcodeToString[final.Rcode], answers+","+nss+","+extras)
	w.WriteMsg(final)

}

var upstreams []string
var timeout time.Duration

var delay time.Duration
var tries int
var retry bool
var net string

var errors map[string]int

func main() {
	timeoutMs := flag.Int("timeout", 200, "timeout")

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
