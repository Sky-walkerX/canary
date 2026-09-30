//go:build uidev

// Command canary-uidev serves the Canary dashboard over sample data, for
// working on the design without a regtest node. Every page it serves carries
// a "SAMPLE DATA" watermark. It builds only with the uidev tag:
//
//	go run -tags uidev ./cmd/canary-uidev
//	go run -tags uidev ./cmd/canary-uidev -scenario stale -addr 127.0.0.1:7353
//
// Scenarios: sample, clear, stale, missing, unreadable, newer. With -touch,
// it rewrites the state file on that interval so open pages show the update
// bar.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Sky-walkerX/canary/internal/ui"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:7353", "listen address, loopback only")
	scenario := flag.String("scenario", "sample", "one of: "+strings.Join(ui.SampleScenarios, ", "))
	dir := flag.String("dir", "", "directory for the sample state and evidence files (default: a new temporary directory)")
	touch := flag.Duration("touch", 0, "rewrite the state file on this interval, for example 20s (0 means never)")
	build := flag.String("build", "dev", "build id suffix the dashboard reports")
	flag.Parse()

	if err := ui.CheckAddr(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "canary-uidev:", err)
		os.Exit(2)
	}
	d := *dir
	if d == "" {
		var err error
		d, err = os.MkdirTemp("", "canary-uidev-")
		if err != nil {
			log.Fatalf("canary-uidev: create temporary directory: %v", err)
		}
	}
	statePath, err := ui.WriteSample(d, *scenario, time.Now())
	if err != nil {
		log.Fatalf("canary-uidev: write sample: %v", err)
	}
	if *touch > 0 {
		go func() {
			for range time.Tick(*touch) {
				if _, err := ui.WriteSample(d, *scenario, time.Now()); err != nil {
					log.Printf("canary-uidev: rewrite sample: %v", err)
				}
			}
		}()
	}

	h, err := ui.New(ui.Options{
		StatePath: statePath,
		Version:   "0.1.0",
		Build:     *build,
		Verify:    ui.SampleVerify,
	})
	if err != nil {
		log.Fatalf("canary-uidev: %v", err)
	}
	fmt.Printf("canary-uidev: serving SAMPLE DATA from %s\n", statePath)
	fmt.Printf("canary-uidev: open http://%s/\n", *addr)
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("canary-uidev: %v", err)
	}
}
