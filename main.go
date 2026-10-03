package main

import (
	"flag"
	"log"
)

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	res := newResolver(cfg)
	log.Fatal(serve(cfg, res))
}
