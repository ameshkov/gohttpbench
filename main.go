// Package main is responsible for the command-line interface.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/AdguardTeam/golibs/log"
	goFlags "github.com/jessevdk/go-flags"
	"go.uber.org/ratelimit"
)

// VersionString is the version that we'll print to the output. See the makefile
// for more details.
var VersionString = "undefined"

// printEveryNRecords regulates when we should print the intermediate results.
const printEveryNRecords = 100

// Options represents console arguments.
type Options struct {
	// URL of the server you're trying to test
	URL string `short:"u" long:"url" description:"URL of the server that needs to be benched." optional:"false"`

	// Connections is the number of connections you would like to open
	// simultaneously.
	Connections int `short:"p" long:"parallel" description:"The number of parallel connections that needs to be used." default:"1"`

	// Timeout is timeout for an HTTP request.
	Timeout int `short:"t" long:"timeout" description:"HTTP request timeout in seconds" default:"10"`

	// Rate sets the rate limit for requests that are sent to the URL.
	Rate int `short:"r" long:"rate-limit" description:"Rate limit (per second)" default:"0"`

	// RequestsCount is the overall number of requests that should be sent.
	RequestsCount int `short:"c" long:"count" description:"The overall number of requests that should be sent" default:"10000"`

	// InsecureSkipVerify controls whether gohttpbench validates server
	// certificate or allows connections with servers with self-signed certs.
	InsecureSkipVerify bool `long:"insecure" description:"Do not validate the server certificate" optional:"yes" optional-value:"true"`

	// Log settings
	// --

	// Verbose defines whether we should write the DEBUG-level log or not.
	Verbose bool `short:"v" long:"verbose" description:"Verbose output (optional)" optional:"yes" optional-value:"true"`

	// LogOutput is the optional path to the log file.
	LogOutput string `short:"o" long:"output" description:"Path to the log file. If not set, write to stdout."`
}

// String implements fmt.Stringer interface for Options.
func (o *Options) String() (s string) {
	b, _ := json.MarshalIndent(o, "", "    ")
	return string(b)
}

func main() {
	for _, arg := range os.Args {
		if arg == "--version" {
			fmt.Printf("gohttpbench version: %s\n", VersionString)
			os.Exit(0)
		}
	}

	options := &Options{}
	parser := goFlags.NewParser(options, goFlags.Default)
	_, err := parser.Parse()
	if err != nil {
		if errors.Is(err, goFlags.ErrHelp) {
			os.Exit(0)
		}

		os.Exit(1)
	}

	state := run(options)

	log.Info("The test results are:")

	elapsed := state.elapsed()
	log.Info("Elapsed: %s", elapsed)
	log.Info("Average RPS: %f", state.rpsTotal())
	log.Info("Processed requests: %d", state.processed)
	log.Info("Average per request: %s", state.elapsedPerRequest())
	log.Info("Errors count: %d", state.errors)
}

// runState represents the overall bench run state and is shared among each
// worker goroutine.
type runState struct {
	// rate limits the queries per second.
	rate ratelimit.Limiter

	// startTime is the time when the test has been started.
	startTime time.Time
	// processed is the number of requests successfully processed.
	processed int
	// errors is the number of requests that failed.
	errors int
	// requestsToSend is the number of requests left to send.
	requestsToSend int
	// requestsSent is the number of requests sent.
	requestsSent int

	// lastPrintedState is the last time we printed the intermediate state.
	// It is printed on every 100's query.
	lastPrintedState     time.Time
	lastPrintedProcessed int
	lastPrintedErrors    int

	// m protects all fields.
	m sync.Mutex
}

// rpsTotal returns the number of requests processed in one second.
func (r *runState) rpsTotal() (q float64) {
	r.m.Lock()
	defer r.m.Unlock()

	e := r.elapsed()

	return float64(r.processed+r.errors) / e.Seconds()
}

// elapsed returns total elapsed time.
func (r *runState) elapsed() (e time.Duration) {
	return time.Now().Sub(r.startTime)
}

// elapsedPerRequest returns elapsed time per query.
func (r *runState) elapsedPerRequest() (e time.Duration) {
	elapsed := r.elapsed()
	avgElapsed := elapsed
	if r.processed > 0 {
		avgElapsed = elapsed / time.Duration(r.processed)
	}

	return avgElapsed
}

// incProcessed increments processed number, returns the new value.
func (r *runState) incProcessed() (p int) {
	r.m.Lock()
	defer r.m.Unlock()

	r.processed++
	r.printIntermediateResults()

	return r.processed
}

// printIntermediateResults prints intermediate results if needed.  This method
// must be protected by the mutex on the outside.
func (r *runState) printIntermediateResults() {
	// Time to print the intermediate result and rps.
	queriesCount := r.processed + r.errors - r.lastPrintedProcessed - r.lastPrintedErrors

	if queriesCount%printEveryNRecords == 0 {
		startTime := r.lastPrintedState
		if r.lastPrintedState.IsZero() {
			startTime = r.startTime
		}

		elapsed := time.Now().Sub(startTime)
		rps := float64(queriesCount) / elapsed.Seconds()

		log.Info("Processed %d requests, errors: %d", r.processed, r.errors)
		log.Info("Requests per second: %f", rps)
		r.lastPrintedState = time.Now()
		r.lastPrintedProcessed = r.processed
		r.lastPrintedErrors = r.errors
	}
}

// incErrors increments errors number, returns the new value.
func (r *runState) incErrors() (e int) {
	r.m.Lock()
	defer r.m.Unlock()

	r.errors++
	r.printIntermediateResults()

	return r.errors
}

// decRequestsToSend decrements requestsToSend number, returns the new value.
func (r *runState) decRequestsToSend() (c int) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.requestsToSend > 0 {
		r.requestsToSend--
		r.requestsSent++

		return r.requestsToSend + 1
	}

	return r.requestsToSend
}

// run is basically the entry point of the program that interprets the
// command-line arguments and runs the bench.
func run(options *Options) (state *runState) {
	if options.Verbose {
		log.SetLevel(log.DEBUG)
	}
	if options.LogOutput != "" {
		file, err := os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer log.OnCloserError(file, log.DEBUG)
		log.SetOutput(file)
	}

	log.Info("Run gohttpbench with the following configuration:\n%s", options)

	// This call is just to validate the request details.
	_, err := http.NewRequest(http.MethodGet, options.URL, nil)
	if err != nil {
		log.Fatalf("The server address %s is invalid: %v", options.URL, err)
	}

	// Subscribe to the OS events.
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)

	var rate ratelimit.Limiter
	if options.Rate > 0 {
		rate = ratelimit.New(options.Rate)
	} else {
		rate = ratelimit.NewUnlimited()
	}

	state = &runState{
		startTime:      time.Now(),
		requestsToSend: options.RequestsCount,
		rate:           rate,
	}

	// Subscribe to the bench run close event.
	closeChannel := make(chan bool, 1)

	// Run it in a separate goroutine so that we could react to other signals.
	go func() {
		log.Info(
			"Starting the test and running %d connections in parallel",
			options.Connections,
		)
		var wg sync.WaitGroup
		for i := 0; i < options.Connections; i++ {
			wg.Add(1)
			go func() {
				runConnection(options, state)
				wg.Done()
			}()
		}
		wg.Wait()

		log.Info("Finished running all connections")
		close(closeChannel)
	}()

	select {
	case <-signalChannel:
		log.Info("The test has been interrupted.")
	case <-closeChannel:
		log.Info("The test has finished.")
	}

	return state
}

// sendRequest sends an HTTP request and reads and closes the response body.
//
// It returns an error if something unexpected happens.
func sendRequest(client *http.Client, req *http.Request) (err error) {
	var resp *http.Response
	resp, err = client.Do(req)

	if err != nil {
		return err
	}

	if resp.Body == nil {
		return nil
	}

	defer log.OnCloserError(resp.Body, log.DEBUG)
	_, err = io.Copy(io.Discard, resp.Body)

	return err
}

// runConnection runs a single connection that sends requests to the specified
// URL as fast as possible until the global limit is reached.
//
// The function takes care of the rate limiting and the global state of the
// program.
func runConnection(options *Options, state *runState) {
	// Ignoring the error here since upstream address was already verified.
	client := &http.Client{
		Timeout: time.Duration(options.Timeout) * time.Second,
	}

	if options.InsecureSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	defer client.CloseIdleConnections()

	for requestsToSend := state.decRequestsToSend(); requestsToSend > 0; {
		// Make sure we don't run faster than the pre-defined rate limit.
		state.rate.Take()

		// Send the HTTP request.
		req, err := http.NewRequest(http.MethodGet, options.URL, nil)

		if err == nil {
			err = sendRequest(client, req)
		}

		if err == nil {
			_ = state.incProcessed()
		} else {
			_ = state.incErrors()

			log.Debug("error occurred: %v", err)
		}

		requestsToSend = state.decRequestsToSend()
	}
}
