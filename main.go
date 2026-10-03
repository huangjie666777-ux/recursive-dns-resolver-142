package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON configuration file")
	demo := flag.Bool("demo", false, "run the local multi-level authoritative demo")
	flag.Parse()

	if *demo {
		runDemo()
		return
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	resolver := NewResolver(cfg)
	srv := NewServer(cfg, resolver)
	log.Printf("recursive resolver listening on %s (udp/tcp), upstream port %d, roots %v",
		cfg.ListenAddr, cfg.UpstreamPort, cfg.RootHints)

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		srv.Shutdown()
	}()
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "server stopped:", err)
	}
}
