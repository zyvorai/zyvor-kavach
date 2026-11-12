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
			go poller.Run(context.Background())
		}
		handler := edr.APIWithCredentials(token, store, registry)
		log.Printf("Kavach API listening on %s (sensor probe: %s)", *listen, edr.ProbeSensor())
		if (*tlsCert == "") != (*tlsKey == "") {
			log.Fatal("TLS certificate and key must be supplied together")
		}
		if *tlsCert == "" {
			if !strings.HasPrefix(*listen, "127.0.0.1:") && !strings.HasPrefix(*listen, "localhost:") {
				log.Fatal("non-loopback listener requires TLS")
			}
			log.Fatal(http.ListenAndServe(*listen, handler))
		}
		cfg, err := edr.ServerTLSConfig(*clientCA)
		if err != nil {
			log.Fatal(err)
		}
		srv := &http.Server{Addr: *listen, Handler: handler, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
		log.Fatal(srv.ListenAndServeTLS(*tlsCert, *tlsKey))
	case "agent":
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		if *url != "http://127.0.0.1:8099" && *url != "http://localhost:8099" && len(*url) >= 7 && (*url)[:7] == "http://" {
			log.Fatal("remote server requires HTTPS")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
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
