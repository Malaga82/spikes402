//go:build windows

package main

import (
	"github.com/Choffolo/spikes402/internal/admin"
	"github.com/Choffolo/spikes402/internal/gate"
)

func watchReload(string, *gate.Gate, *admin.Server) {}
