package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	wildcard "github.com/IGLOU-EU/go-wildcard"
	"github.com/docker/docker/pkg/ioutils"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shuffledUpstreams := make([]string, len(currentUpstreams))
	copy(shuffledUpstreams, currentUpstreams)

	rand.Shuffle(len(shuffledUpstreams), func(i, j int) {
		shuffledUpstreams[i], shuffledUpstreams[j] = shuffledUpstreams[j], shuffledUpstreams[i]
	})

	responses := make(chan *dns.Msg, len(shuffledUpstreams))

	for i, upstream := range shuffledUpstreams {
		go func(index int, upstream string, question dns.Question) {
			if concurrencyDelay > 0 {
				myConcurrencyDelay := time.Duration(concurrencyDelay) * time.Duration(index)
				select {
				case <-ctx.Done():
					return
				case <-time.After(myConcurrencyDelay):
				}
			}

			try := 0
			currentNet := netMode
			for try < tries {
				select {
				case <-ctx.Done():
					return
				default:
				}

				response, rtt, err := resolve(upstream, question, recursionDesired, currentNet)

				select {
				case <-ctx.Done():
					return
				default:
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
					} else if len(response.Answer) == 0 {
						if len(response.Ns) > 0 {
							logger(id, "EMPTYNS", question, upstream, rtt.String(), strconv.Itoa(try))
							responses <- response
							return
						} else {
							logger(id, "EMPTY", question, upstream, rtt.String(), strconv.Itoa(try))
						}
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

				select {
				case <-ctx.Done():
					return
				default:
				}

				try = try + 1
				// retry truncated instantly
				if response == nil {
					time.Sleep(delay)
				}

				select {
				case <-ctx.Done():
					return
				default:
				}

				if currentNet == "udp" {
					currentNet = "tcp"
				}
				logger(id, "RETRY", question, upstream, currentNet, strconv.Itoa(try))
			}

			responses <- nil
		}(i, upstream, question)
	}

	received := 0
	var final *dns.Msg
	for response := range responses {
		received = received + 1
		if response != nil {
			final = response
			break
		}

		if received == len(shuffledUpstreams) {
			break
		}
	}

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
func reloadHosts(hostsPath string) {
	if hostsPath == "" {
		return
	}

	if b, err := ioutil.ReadFile(hostsPath); err != nil {
		log.Fatalln("failed to read", hostsPath, err)
	} else {
		if err := json.Unmarshal(b, &hosts); err != nil {
			log.Fatalln("failed to parse", hostsPath, err)
		}
	}
}

func createResponse(rrs []dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.Compress = false
	response.RecursionAvailable = true

	for _, rr := range rrs {
		response.Answer = append(response.Answer, rr)
	}

	return response
}

func handleDnsRequest(w dns.ResponseWriter, request *dns.Msg) {
	id := uuid.New().String()
	var final *dns.Msg

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

		final = createResponse([]dns.RR{rr})
	}

	if final == nil {
		switch question.Qtype {
		case dns.TypeA, dns.TypeAAAA:
			for host, values := range hosts[dns.Type(question.Qtype).String()] {
				if wildcard.Match(host, question.Name) {
					logger(id, "HOSTS", question)
					var rrs []dns.RR
					for _, value := range values {
						rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN %s %s\n", question.Name, 3600, dns.Type(question.Qtype).String(), value))
						rrs = append(rrs, rr)
					}
					final = createResponse(rrs)
					break
				}
			}
		}
	}

	if final == nil {
		var currentUpstreams []string
		if strings.Count(question.Name, ".") == 1 {
			if resolvSearch != "" {
				question.Name = question.Name + resolvSearch + "."
			}
			currentUpstreams = resolvUpstreams
		} else {
			currentUpstreams = upstreams
		}

		logger(id, "QUERY", question, "recursion", strconv.FormatBool(request.RecursionDesired))
		response := harder(id, question, request.RecursionDesired, currentUpstreams)

		if response != nil {
			final = response
		} else {
			final = createResponse([]dns.RR{})
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

var hosts = make(map[string]map[string][]string)

var upstreams []string
var dialTimeout time.Duration
var readTimeout time.Duration
var writeTimeout time.Duration

var delay time.Duration
var concurrencyDelay time.Duration
var tries int
var retry bool
var netMode string
var edns0 int
var stats int
var events map[string]map[string]int
var resolv bool
var resolvUpstreams []string
var resolvSearch string
var devMode bool

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

	delayMs := flag.Int("delay", 10, "retry delay in ms")
	concurrencyDelayMs := flag.Int("concurrencyDelay", 0, "concurrency delay in ms, first upstream immediately and then add every delay (default 0)")

	flag.IntVar(&tries, "tries", 3, "tries")
	flag.BoolVar(&retry, "retry", false, "retry")
	flag.StringVar(&netMode, "netMode", "udp", "udp, tcp, tcp-tls")

	flag.IntVar(&edns0, "edns0", -1, "edns0")
	flag.IntVar(&stats, "stats", -1, "print stats every N seconds")

	flag.BoolVar(&resolv, "resolv", false, "resolv")
	flag.StringVar(&resolvSearch, "resolvSearch", "", "resolvSearch")
	flag.BoolVar(&devMode, "devMode", false, "devMode")

	var hostsPath string
	flag.StringVar(&hostsPath, "hosts", "", "hosts")

	flag.Parse()

	reloadSigs := make(chan os.Signal, 1)
	signal.Notify(reloadSigs, syscall.SIGHUP)
	go func() {
		for {
			<-reloadSigs
			reloadHosts(hostsPath)
		}
	}()

	dialTimeout = time.Millisecond * time.Duration(*dialTimeoutMs)
	readTimeout = time.Millisecond * time.Duration(*readTimeoutMs)
	writeTimeout = time.Millisecond * time.Duration(*writeTimeoutMs)

	delay = time.Millisecond * time.Duration(*delayMs)
	concurrencyDelay = time.Millisecond * time.Duration(*concurrencyDelayMs)
	statsDelay := time.Second * time.Duration(stats)

	upstreams = flag.Args()
	if len(upstreams) == 0 {
		log.Fatalln("no upstreams")
	}

	if resolv {
		var currentResolvConf string
		if devMode {
			currentResolvConf = "/tmp/resolv.conf"
			err := ioutil.WriteFile(currentResolvConf, []byte("# before harderdns\nnameserver 138.197.68.199\n"), 06644)
			if err != nil {
				log.Fatalln("failed to write ", currentResolvConf, "err", err)
			}
		} else {
			currentResolvConf = "/etc/resolv.conf"
		}

		resolvContents, err := ioutil.ReadFile(currentResolvConf)
		if err != nil {
			log.Fatalln("failed to read", currentResolvConf, err)
		}
		resolvHash, err := ioutils.HashData(bytes.NewReader(resolvContents))
		if err != nil {
			log.Fatalln("failed to hash", resolvContents, err)
		}
		f := resolvconf.File{
			Content: resolvContents,
			Hash:    resolvHash,
		}

		for _, resolvUpstream := range resolvconf.GetNameservers(f.Content) {
			if resolvUpstream == "127.0.0.1" {
				continue
			}
			resolvUpstreams = append(resolvUpstreams, resolvUpstream+":53")
		}

		err = ioutil.WriteFile(currentResolvConf, []byte("# managed by harderdns\nnameserver 127.0.0.1\n"), 06444)
		if err != nil {
			log.Fatalln("failed to write " + currentResolvConf)
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

	reloadHosts(hostsPath)

	dns.HandleFunc(".", handleDnsRequest)

	port := 53
	server := &dns.Server{
		Addr: "0.0.0.0:" + strconv.Itoa(port),
		Net:  "udp",
	}
	defer server.Shutdown()

	log.Printf("Starting at :%d using %s\n", port, netMode)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}
