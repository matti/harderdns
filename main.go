package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/libnetwork/resolvconf"
	"github.com/google/uuid"
	"github.com/miekg/dns"
)

func resolve(upstream string, question dns.Question, recursionDesired bool, currentNet string) (*dns.Msg, time.Duration, error) {
	c := dns.Client{
		DialTimeout:  dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,

		Net: currentNet,
	}

	query := &dns.Msg{}
	query.SetQuestion(question.Name, question.Qtype)
	query.RecursionDesired = recursionDesired

	if edns0 > -1 {
		query.SetEdns0(uint16(edns0), false)
	}

	return c.Exchange(query, upstream)
}

var eventMutex sync.Mutex

func event(upstream string, name string) {
	defer eventMutex.Unlock()

	eventMutex.Lock()
	events[upstream][name] = events[upstream][name] + 1
}

func harder(id string, question dns.Question, recursionDesired bool, currentUpstreams []string) *dns.Msg {
	stop := false
	responses := make(chan *dns.Msg, len(currentUpstreams))

	for _, upstream := range currentUpstreams {
		go func(upstream string, question dns.Question) {
			try := 0
			currentNet := netMode
			for try < tries {
				if stop {
					return
				}
				response, rtt, err := resolve(upstream, question, recursionDesired, currentNet)
				if stop {
					return
				}

				if err == nil {
					if response.Truncated {
						event(upstream, "trunc")
						logger(id, "TRUNC", question, upstream, rtt.String(), strconv.Itoa(try))
						// https://serverfault.com/questions/991520/how-is-truncation-performed-in-dns-according-to-rfc-1035/991563#991563
						currentNet = "tcp"

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
						event(upstream, "got")
						logger(id, "GOT", question, upstream, rtt.String(), strconv.Itoa(try))
						responses <- response
						return
					}
				} else {
					event(upstream, "error")
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

		if received == len(currentUpstreams) {
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

		var currentUpstreams []string
		if strings.Count(question.Name, ".") == 1 {
			println("sellanen")
			currentUpstreams = resolvUpstreams
		} else {
			currentUpstreams = upstreams
		}
		response := harder(id, question, request.RecursionDesired, currentUpstreams)
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
var netMode string
var edns0 int
var stats int
var events map[string]map[string]int
var resolv bool
var resolvUpstreams []string

func main() {
	log.Println(os.Args)
	if len(os.Args) > 1 && os.Args[1] == "test" {
		name := os.Args[2]
		for {
			const timeout = 100 * time.Millisecond
			ctx, _ := context.WithTimeout(context.TODO(), timeout)

			var r net.Resolver
			startedAt := time.Now()
			ips, err := r.LookupIP(ctx, "ip4", name)
			if err != nil {
				log.Println("test error", err)
			} else {
				log.Println("test", name, "resolves", ips)
				os.Exit(0)
			}

			took := time.Since(startedAt)
			remaining := (time.Millisecond * 100) - took

			if remaining > 0 {
				time.Sleep(remaining)
			}
		}
	}

	dialTimeoutMs := flag.Int("dialTimeout", 101, "dialTimeout")
	readTimeoutMs := flag.Int("readTimeout", 500, "readTimeout")
	writeTimeoutMs := flag.Int("writeTimeout", 500, "writeTimeout")

	delayMs := flag.Int("delay", 10, "delay in ms")
	flag.IntVar(&tries, "tries", 3, "tries")
	flag.BoolVar(&retry, "retry", false, "retry")
	flag.StringVar(&netMode, "netMode", "udp", "udp, tcp, tcp-tls")

	flag.IntVar(&edns0, "edns0", -1, "edns0")
	flag.IntVar(&stats, "stats", -1, "print stats every N seconds")

	flag.BoolVar(&resolv, "resolv", false, "resolv")
	flag.Parse()

	dialTimeout = time.Millisecond * time.Duration(*dialTimeoutMs)
	readTimeout = time.Millisecond * time.Duration(*readTimeoutMs)
	writeTimeout = time.Millisecond * time.Duration(*writeTimeoutMs)

	delay = time.Millisecond * time.Duration(*delayMs)
	statsDelay := time.Second * time.Duration(stats)

	upstreams = flag.Args()
	if len(upstreams) == 0 {
		log.Fatalln("no upstreams")
	}
	if resolv {
		f, err := resolvconf.Get()
		if err != nil {
			log.Fatalln("failed to read resolvconf")
		}

		for _, resolvUpstream := range resolvconf.GetNameservers(f.Content) {
			resolvUpstreams = append(resolvUpstreams, resolvUpstream+":53")
		}

		err = ioutil.WriteFile("/etc/resolv.conf", []byte("# managed by harderdns\nnameserver 127.0.0.1\n"), 06444)
		if err != nil {
			log.Fatalln("failed to write /etc/resolv.conf")
		}
	}
	events = make(map[string]map[string]int)
	for _, upstream := range append(upstreams, resolvUpstreams...) {
		events[upstream] = make(map[string]int)
	}

	go func() {
		if statsDelay < 0 {
			return
		}
		for {
			loggerMutex.Lock()
			for _, upstream := range upstreams {
				log.Println("upstream", upstream, "got", events[upstream]["got"], "error", events[upstream]["error"], "trunc", events[upstream]["trunc"])
			}
			for _, resolvUpstream := range resolvUpstreams {
				log.Println("upstream", resolvUpstream, "got", events[resolvUpstream]["got"], "error", events[resolvUpstream]["error"], "trunc", events[resolvUpstream]["trunc"])
			}
			loggerMutex.Unlock()
			time.Sleep(statsDelay)
		}
	}()

	dns.HandleFunc(".", handleDnsRequest)

	port := 53
	server := &dns.Server{
		Addr: ":" + strconv.Itoa(port),
		Net:  "udp",
	}
	defer server.Shutdown()

	log.Printf("Starting at :%d using %s\n", port, netMode)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
