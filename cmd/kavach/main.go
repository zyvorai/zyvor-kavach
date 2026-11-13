package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/zyvorai/zyvor-kavach/internal/edr"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	mode := flag.String("mode", "server", "server or agent")
	listen := flag.String("listen", "127.0.0.1:8099", "API listen address")
	url := flag.String("url", "http://127.0.0.1:8099", "server URL (HTTPS required for remote hosts)")
	state := flag.String("state", "./data/findings.jsonl", "persistent finding file")
	queue := flag.String("queue", "./data/outbox", "durable agent event queue directory")
	registryPath := flag.String("credentials", "./data/agents.json", "hashed host credential registry (server)")
	tlsCert := flag.String("tls-cert", "", "server TLS certificate PEM")
	tlsKey := flag.String("tls-key", "", "server TLS private key PEM")
	clientCA := flag.String("client-ca", "", "optional client CA for mTLS on server")
	ca := flag.String("ca", "", "agent trusted CA bundle")
	agentCert := flag.String("agent-cert", "", "agent client certificate PEM")
	agentKey := flag.String("agent-key", "", "agent client key PEM")
	fileRoot := flag.String("watch-files", "", "opt-in file metadata watch directory")
	period := flag.Duration("interval", 3*time.Second, "process polling interval")
	flag.Parse()
	token := os.Getenv("KAVACH_TOKEN")
	if token == "" {
		token = os.Getenv("ZYVOR_EDR_TOKEN") // legacy alias
	}
	if len(token) < 8 {
		log.Fatal("set KAVACH_TOKEN to a secret of at least 8 characters")
	}
	switch *mode {
	case "server":
		store, err := edr.NewStore(*state, 1000)
		if err != nil {
			log.Fatal(err)
		}
		registry, err := edr.OpenCredentialRegistry(*registryPath)
		if err != nil {
			log.Fatal(err)
		}
		if poller := edr.NewNetraPollerFromEnv(); poller != nil {
			go poller.Run(edr.LifecycleContext()) // cancelled by StopAll
		}
		handler := edr.APIWithCredentials(token, store, registry)
		log.Printf("Kavach API listening on %s (sensor probe: %s)", *listen, edr.ProbeSensor())
		if (*tlsCert == "") != (*tlsKey == "") {
			log.Fatal("TLS certificate and key must be supplied together")
		}
		srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		if *tlsCert == "" {
			if !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "localhost:") {
				log.Fatal("non-loopback listener requires TLS")
			}
		} else {
			cfg, err := edr.ServerTLSConfig(*clientCA)
			if err != nil {
				log.Fatal(err)
			}
			srv.TLSConfig = cfg
		}
		sigCtx, stopSig := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stopSig()
		errCh := make(chan error, 1)
		go func() {
			if *tlsCert == "" {
				errCh <- srv.ListenAndServe()
			} else {
				errCh <- srv.ListenAndServeTLS(*tlsCert, *tlsKey)
			}
		}()
		select {
		case err := <-errCh:
			log.Fatal(err) // listener failed before any signal (e.g. address in use)
		case <-sigCtx.Done():
		}
		stopSig() // a second signal now kills the process the default way
		shutdownServer(srv)
		return
	case "agent":
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		if *url != "http://127.0.0.1:8099" && *url != "http://localhost:8099" && len(*url) >= 7 && (*url)[:7] == "http://" {
			log.Fatal("remote server requires HTTPS")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fmt.Printf("Kavach observation-only agent on %s\n", host)
		client, err := edr.NewMutualTLSClient(*ca, *agentCert, *agentKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal(edr.RunAgentWithOptions(ctx, edr.NewScanner("/proc", host), *url, token, *period, edr.Queue{Dir: *queue, Limit: 10000}, client, *fileRoot))
	default:
		log.Fatal("invalid mode")
	}
}

// Shutdown budget. Helm terminationGracePeriodSeconds is 20 s; the worst case below is
// httpDrain (7 s) + stopBudget (5 s) = 12 s, so 15 s is never exceeded: both phases run on
// context deadlines, per-stopper timeouts (edr.StopTimeout = 2 s) are clamped by stopBudget, and
// a hung HTTP drain (e.g. long-lived SSE streams) falls through to srv.Close().
const (
	httpDrain  = 7 * time.Second
	stopBudget = 5 * time.Second
)

func shutdownServer(srv *http.Server) {
	log.Print("shutdown: signal received, draining")
	edr.BeginShutdown() // /readyz -> 503 immediately so load balancers stop routing
	ctx, cancel := context.WithTimeout(context.Background(), httpDrain)
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("shutdown: http drain: %v; closing connections", err)
		_ = srv.Close()
	}
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), stopBudget)
	defer scancel()
	for _, r := range edr.StopAll(sctx) {
		if r.TimedOut || r.Err != "" {
			log.Printf("shutdown: %s: timed_out=%v panicked=%v err=%s", r.Name, r.TimedOut, r.Panicked, r.Err)
		}
	}
	log.Print("shutdown: complete")
}
