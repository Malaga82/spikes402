package config

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Lottery turns proof-of-work into Bitcoin solo mining: the gate connects to
// a solo pool over stratum, and every sha256d challenge also comes as a real
// block header. If a visitor's or a bot's hash ever clears the network
// target, the pool pays the block to Address. Off unless Pool is set.
type Lottery struct {
	Pool     string `json:"pool"`     // stratum address: "host:port" or "tls://host:port", e.g. "solo.ckpool.org:3333"
	Address  string `json:"address"`  // Bitcoin address the block reward goes to (public: shown on the dashboard)
	Worker   string `json:"worker"`   // optional worker name, sent as "address.worker"
	Password string `json:"password"` // pool password, usually ignored; default "x"
}

// On reports whether the lottery is configured.
func (l Lottery) On() bool { return l.Pool != "" }

// User is the pool user name: the address, and the worker if any.
func (l Lottery) User() string {
	if l.Worker == "" {
		return l.Address
	}
	return l.Address + "." + l.Worker
}

// A format check for mainnet and testnet addresses (legacy, script, bech32
// and bech32m), to catch typos and pasted URLs; the pool checks the rest.
var (
	btcAddress = regexp.MustCompile(`^([13mn2][1-9A-HJ-NP-Za-km-z]{25,34}|(bc|tb|bcrt)1[02-9ac-hj-np-z]{11,87})$`)
	workerName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
)

func (c *Config) checkLottery() error {
	l := &c.Lottery
	if !l.On() {
		if *l != (Lottery{}) {
			return errors.New(`"lottery" needs "pool"`)
		}
		return nil
	}
	hostPort := strings.TrimPrefix(strings.TrimPrefix(l.Pool, "tls://"), "tcp://")
	if host, port, err := net.SplitHostPort(hostPort); err != nil || host == "" || port == "" {
		return fmt.Errorf(`"lottery.pool" must be "host:port" or "tls://host:port", not %q`, l.Pool)
	}
	if !btcAddress.MatchString(l.Address) {
		return errors.New(`"lottery.address" must be a Bitcoin address (1..., 3..., bc1...)`)
	}
	if l.Worker != "" && !workerName.MatchString(l.Worker) {
		return errors.New(`"lottery.worker" may only hold letters, digits, "_" and "-" (32 at most)`)
	}
	if l.Password == "" {
		l.Password = "x"
	}
	return nil
}
