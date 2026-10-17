//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bug0000/pingtun/internal/carrier"
	"github.com/bug0000/pingtun/internal/config"
	"github.com/bug0000/pingtun/internal/probe"
)

func probeCommand(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", "", "private config; only carrier key and IPv4 addresses are used")
	duration := fs.Duration("duration", 10*time.Second, "bounded measurement duration (server also stops automatically)")
	size := fs.Int("size", 1280, "total IPv4 wire size, 94..1500 bytes")
	pps := fs.Int("pps", 100, "requests per second (1..5000)")
	window := fs.Int("window", 256, "maximum outstanding requests (1..1024)")
	timeout := fs.Duration("timeout", time.Second, "request timeout and final drain period")
	idMode := fs.String("id-mode", "stable", "stable ICMP ID or rotate for every request")
	maxPPS := fs.Int("max-pps", 5000, "server admission rate; 32-request burst allowance")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected probe argument")
	}
	if *duration < 100*time.Millisecond || *duration > 2*time.Minute {
		return errors.New("probe duration must be 100ms..2m")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	cc, err := c.Carrier()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if command == "probe-server" {
		if c.Role != "server" || *maxPPS < 1 || *maxPPS > 5000 {
			return errors.New("probe-server requires server role and max-pps 1..5000")
		}
		ctx, cancel := context.WithTimeout(ctx, *duration)
		defer cancel()
		s, err := carrier.Listen(c.Listen)
		if err != nil {
			return err
		}
		r, runErr := probe.Serve(ctx, s, probe.ServerOptions{Key: cc.Key, MaxPPS: *maxPPS})
		if err = json.NewEncoder(os.Stdout).Encode(r); err != nil {
			return err
		}
		return runErr
	}
	if c.Role != "client" {
		return errors.New("probe requires client role")
	}
	o := probe.Options{Key: cc.Key, Remote: cc.Remote, Size: *size, PPS: *pps, Window: *window, Duration: *duration, Timeout: *timeout, IDMode: *idMode}
	if err = o.Validate(); err != nil {
		return err
	}
	s, err := carrier.Listen(c.Listen)
	if err != nil {
		return err
	}
	r, runErr := probe.Run(ctx, s, o)
	if err = json.NewEncoder(os.Stdout).Encode(r); err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if r.Verified == 0 {
		return errors.New("no authenticated probe responses; inspect kernel echoes, filtering and server state")
	}
	return nil
}
