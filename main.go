package main

import (
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
)

func resolve(upstream string, question dns.Question, recursionDesired bool) (*dns.Msg, time.Duration, error) {
	c := dns.Client{
		DialTimeout:  dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,

		Net: net,
	}

	query := &dns.Msg{}
	query.SetQuestion(question.Name, question.Qtype)
	query.RecursionDesired = recursionDesired

	if edns0 > -1 {
		query.SetEdns0(uint16(edns0), false)
	}

	return c.Exchange(query, upstream)
}

func harder(id string, question dns.Question, recursionDesired bool) *dns.Msg {
	stop := false
	responses := make(chan *dns.Msg, len(upstreams))

	for _, upstream := range upstreams {
		go func(upstream string, question dns.Question) {
			try := 0

			for try < tries {
				if stop {
					return
				}
				response, rtt, err := resolve(upstream, question, recursionDesired)
				if stop {
					return
				}

				if err == nil {
					if response.Truncated {
						logger(id, "TRUNC", question, upstream, rtt.String(), strconv.Itoa(try))
						// log.Println(
						// 	"Answer", response.Answer,
						// 	"AuthenticatedData", response.AuthenticatedData,
						// 	"Authoritative", response.Authoritative,
						// 	"CheckingDisabled", response.CheckingDisabled,
						// 	"Compress", response.Compress,
						// 	"Extra", response.Extra,
						// 	"Id", response.Id,
						// 	"MsgHdr", response.MsgHdr,
						// 	"Ns", response.Ns,
						// 	"Opcode", response.Opcode,
						// 	"Question", response.Question,
						// 	"Rcode", response.Rcode,
						// 	"RecursionAvailable", response.RecursionAvailable,
						// 	"RecursionDesired", response.RecursionDesired,
						// 	"Response", response.Response,
						// 	"Truncated", response.Truncated,
						// 	"Zero", response.Zero,
						// )
					} else {
						logger(id, "GOT", question, upstream, rtt.String(), strconv.Itoa(try))
						responses <- response
						return
					}
				} else {
					logger(id, "ERROR", question, upstream, fmt.Sprintf("%v", err)+" "+rtt.String())
				}

				try = try + 1
				time.Sleep(delay)
				logger(id, "RETRY", question, upstream, strconv.Itoa(try))
			}

			responses <- nil
		}(upstream, question)
	}

	received := 0
	var final *dns.Msg
	for response := range responses {
		received = received + 1
		if response != nil {
			final = response
			break
		}

		if received == len(upstreams) {
			break
		}
	}

	stop = true
	return final
}

var loggerMutex sync.Mutex

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

	loggerMutex.Lock()
	println(sb.String())
	loggerMutex.Unlock()

}

func createResponse(rr dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.Compress = false
	response.RecursionAvailable = true
	if rr != nil {
		response.Answer = append(response.Answer, rr)
	}
	return response
}

func handleDnsRequest(w dns.ResponseWriter, request *dns.Msg) {
	var final *dns.Msg
	id := uuid.New().String()

	// https://stackoverflow.com/questions/55092830/how-to-perform-dns-lookup-with-multiple-questions
	question := request.Question[0]

	if request.Opcode != dns.OpcodeQuery {
		logger(id, "UNKNOWN", question, dns.OpcodeToString[request.Opcode])
		w.WriteMsg(createResponse(nil))
		return
	}

	switch question.Name {
	case "localhost.":
		logger(id, "LOCAL", question)
		var rr dns.RR
		switch question.Qtype {
		case dns.TypeA:
			rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN A %s\n", question.Name, 3600, "127.0.0.1"))
		case dns.TypeAAAA:
			rr, _ = dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s\n", question.Name, 3600, "::1"))
		}

		final = createResponse(rr)

	default:
		logger(id, "QUERY", question, "recursion", strconv.FormatBool(request.RecursionDesired))
		response := harder(id, question, request.RecursionDesired)
		if response != nil {
			final = response
		} else {
			final = createResponse(nil)
			final.SetRcode(request, dns.RcodeServerFailure)
		}
	}

	answers := strconv.Itoa(len(final.Answer))
	nss := strconv.Itoa(len(final.Ns))
	extras := strconv.Itoa(len(final.Extra))

	logger(id, "ANSWER", question, dns.RcodeToString[final.Rcode], answers+","+nss+","+extras)

	final.SetReply(request)
	w.WriteMsg(final)
}

var upstreams []string
var dialTimeout time.Duration
var readTimeout time.Duration
var writeTimeout time.Duration

var delay time.Duration
var tries int
var retry bool
var net string
var edns0 int

var errors map[string]int

func main() {
	dialTimeoutMs := flag.Int("dialTimeout", 101, "dialTimeout")
	readTimeoutMs := flag.Int("readTimeout", 500, "readTimeout")
	writeTimeoutMs := flag.Int("writeTimeout", 500, "writeTimeout")

	delayMs := flag.Int("delay", 10, "delay in ms")
	flag.IntVar(&tries, "tries", 3, "tries")
	flag.BoolVar(&retry, "retry", false, "retry")
	flag.StringVar(&net, "net", "udp", "udp, tcp, tcp-tls")

	flag.IntVar(&edns0, "edns0", -1, "edns0")

	flag.Parse()

	dialTimeout = time.Millisecond * time.Duration(*dialTimeoutMs)
	readTimeout = time.Millisecond * time.Duration(*readTimeoutMs)
	writeTimeout = time.Millisecond * time.Duration(*writeTimeoutMs)

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
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(port),
		Net:  "udp",
	}
	defer server.Shutdown()

	log.Printf("Starting at :%d using %s\n", port, net)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
