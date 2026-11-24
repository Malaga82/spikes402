//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Choffolo/spikes402/internal/admin"
	"github.com/Choffolo/spikes402/internal/gate"
)

func watchReload(configFile string, g *gate.Gate, adm *admin.Server) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			if err := reloadConfig(configFile, g, adm); err != nil {
				log.Printf("reload failed (keeping current settings): %v", err)
			}
		}
	}()
}
