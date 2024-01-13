// Copyright 2024 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"time"

	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

type TailscaleServer struct {
	Server       *tsnet.Server
	NATSListener net.Listener
	LocalClient  *tailscale.LocalClient
	Options      *TSNetOpts

	// TBD:
	// Client Connect URLs, using (*tsnet.Server).CertDomains() ?
}

const maxTCPPort = 65535

// This will be within the server StoreDir
const tailscaleStateSubdir = "tsnet"

var (
	errTailscaleInvalidPort            = errors.New("tailscale: port is not a valid port number")
	errTailscaleNeedsStoreDir          = errors.New("tailscale: server store_dir must be set")
	errTailscaleNoUserDisposition      = errors.New("tailscale: no configuration to handle user accounts")
	errTailscaleTooManyUserDisposition = errors.New("tailscale: can only put users in one account")
)

func validateTailscaleOptions(o *Options) error {
	if o.Tailscale == nil {
		// Fine, not enabled
		return nil
	}
	if o.Tailscale.Name != _EMPTY_ {
		if err := dnsname.ValidLabel(o.Tailscale.Name); err != nil {
			return fmt.Errorf("NATS validation of Tailscale name: %w", err)
		}
		if o.StoreDir == _EMPTY_ {
			return errTailscaleNeedsStoreDir
		}
	}
	if o.Tailscale.NATSPort == 0 {
		if o.Port < 0 || o.Port == 1 || o.Port > maxTCPPort {
			return errTailscaleInvalidPort
		}
	} else if o.Tailscale.NATSPort < 2 || o.Tailscale.NATSPort > maxTCPPort {
		// We disallow 1, the MUX port, and all negative numbers, and no wrapping
		return errTailscaleInvalidPort
	}

	// Is there anything we should reasonably do to check o.Tailscale.ControlURL ?

	// TBD: should we allow combining MapUsers with a fallback account?
	authDispatch := 0
	if o.Tailscale.UseGlobalNATSAccount {
		authDispatch += 1
	}
	if o.Tailscale.UseNATSAccount != "" {
		// FIXME: how do we look up this account to see if it's valid?
		authDispatch += 1
	}
	if o.Tailscale.MapUsers {
		authDispatch += 1
	}

	switch authDispatch {
	case 1:
		// user configured us, all is right
	case 0:
		return errTailscaleNoUserDisposition
	default:
		return errTailscaleTooManyUserDisposition
	}

	return nil
}

func (o *Options) tailscaleEnabled() bool {
	return o != nil && o.Tailscale != nil && o.Tailscale.Name != _EMPTY_ && o.StoreDir != _EMPTY_
}

func (o *Options) tailscaleNATSPortSpec() string {
	// Caller should only call if TS is enabled, so o.Tailscale must be non-nil
	var port int = o.Tailscale.NATSPort
	if port == 0 {
		port = o.Port
	}
	if port == 0 {
		port = DEFAULT_PORT
	}
	return ":" + strconv.Itoa(port)
}

func (o *Options) newTsNetServer() *tsnet.Server {
	if !o.tailscaleEnabled() {
		return nil
	}
	s := new(tsnet.Server)
	s.Hostname = o.Tailscale.Name
	// We don't want to write to the caller's homedir, so we use the StoreDir.
	// There needs to be a distinct state-dir per server name, so if someone
	// experiments with different names, keep them distinct.
	s.Dir = filepath.Join(o.StoreDir, tailscaleStateSubdir, o.Tailscale.Name)
	s.ControlURL = o.Tailscale.ControlURL
	if o.Tailscale.QuietLogs {
		s.Logf = logger.Discard
	}
	return s
}

func (s *Server) startTailscaleServer() {
	if s.isShuttingDown() {
		return
	}
	sopts := s.getOpts()
	if !sopts.tailscaleEnabled() {
		return
	}

	ts := sopts.newTsNetServer()
	ln, err := ts.Listen("tcp", sopts.tailscaleNATSPortSpec())
	if err != nil {
		ts.Close()
		s.Fatalf("Unable to listen on Tailscale: %w", err)
	}

	// We need to be able to talk _to_ the Tailscale daemon on the local
	// machine, to ask for certs and ask who a given client is.
	lc, err := ts.LocalClient()
	if err != nil {
		ln.Close()
		ts.Close()
		s.Fatalf("Unable to talk to Tailscale: %w", err)
	}

	// NB: if net/netip.IsValid() returns false on these, then we don't have IPs yet, because we're not connected.
	// Really we should figure out a way to check that correctly and pause on the regular flow until done, and use
	// a callback to log these IPs when we finally do have them.
	// FIXME: what _should_ I be doing here?
	ip4, ip6 := ts.TailscaleIPs()
	s.Noticef("Our tailscale IPs are [%v, %v]", ip4, ip6)

	s.mu.Lock()
	s.tsnet = &TailscaleServer{
		Server:       ts,
		NATSListener: ln,
		LocalClient:  lc,
		Options:      &TSNetOpts{},
	}
	// This is a second copy of the options, but these ones definitively match what we connected to Tailscale with, as opposed to what a new setup might use.
	*s.tsnet.Options = *sopts.Tailscale
	s.mu.Unlock()

	if sopts.Tailscale.AllowTLS {
		// Assumption: asking for the cert now will lower the response latency when a user connects, instead of deferring it until first use.
		// FIXME: check this assumption
		for _, dom := range ts.CertDomains() {
			s.Noticef("asking tailscale for TLS cert for domain: %q", dom)
			_, _, err = lc.CertPair(context.Background(), dom)
			if err != nil {
				s.Noticef("tailscale cert for domain %q failed: %v", dom, err)
			}
		}
	}

	go func() {
		defer ts.Close()
		defer ln.Close()
		s.runTailscaleNATSPortMainLoop()
	}()
}

func (s *Server) runTailscaleNATSPortMainLoop() {
	s.mu.Lock()
	tsnet := s.tsnet
	s.mu.Unlock()

	// which listener, a label, an accept func, an error func
	s.acceptConnections(tsnet.NATSListener, "TailClient",
		func(conn net.Conn) { s.createTailscaleClient(conn, tsnet) },
		func(_ error) bool {
			// TBD: Lame Duck Mode, the handling in the regular server assumes that there's only one main listener, so we can't use the handling there.

			// Returning true causes the listener loop to exit
			return false
		},
	)
}

func (s *Server) createTailscaleClient(conn net.Conn, tsnet *TailscaleServer) *client {
	opts := s.getOpts()
	// The tsnet.Options we have is not the one from the opts snapshot there, but the one which was used to talk to tailscale when our listener was created.
	// When would this distinction matter?
	// Should we use opts.UseGlobalNATSAccount and friends below, the auth-handling decisions, to let those be dynamically reloaded?

	ra := conn.RemoteAddr().String()
	whois, err := tsnet.LocalClient.WhoIs(context.TODO(), ra)
	if err != nil {
		s.Noticef("tailscale failed to identify user from %q: %w", ra, err)
		conn.Close()
		return nil
	}
	// whois is tailscale.com/client/tailscale/apitype.WhoIsResponse
	// its .Node and .UserProfile are both in tailscale.com/tailcfg namespace and in non-error are guaranteed non-nil.
	// whois.Node.ComputedName identifies where someone has connected from (FQDN; don't strip it, in case future tailnet bridging makes it matter)
	// whois.UserProfile.LoginName is an email format, .DisplayName is "John Smith" format
	// whois.UserProfile.Groups[] could be used in future work to let someone authenticate to a NATS Account with empty creds and authorize based on group membership?
	//
	// BEWARE: that whois.UserProfile.LoginName doesn't have provider information so we might be doing things all wrong, if a tailnet allows multiple providers?
	// I don't know, but I'm asking.
	s.Debugf("tailscale connection by %q [%q] from %q (%q)", whois.UserProfile.DisplayName, whois.UserProfile.LoginName, whois.Node.ComputedName, ra)
	tsAuthIdentifier := whois.UserProfile.LoginName

	maxPay := int32(opts.MaxPayload)
	maxSubs := int32(opts.MaxSubs)
	// For system, maxSubs of 0 means unlimited, so re-adjust here.
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	c := &client{srv: s, nc: conn, opts: defaultOpts, mpay: maxPay, msubs: maxSubs, start: now, last: now}
	c.opts.Username = tsAuthIdentifier

	s.mu.Lock()
	info := s.copyInfo()
	s.totalClients++
	s.mu.Unlock()

	info.AuthRequired = false
	// It's over Tailscale, TLS is unnecessary, but if they
	info.TLSRequired = false
	info.TLSAvailable = tsnet.Options.AllowTLS

	if tsnet.Options.UseGlobalNATSAccount {
		c.registerWithAccount(s.globalAccount())
		s.Debugf("tailscale->account: %q placed in global account", tsAuthIdentifier)
	} else if tsnet.Options.UseNATSAccount != "" {
		acc, err := s.lookupAccount(tsnet.Options.UseNATSAccount)
		if err != nil {
			s.Errorf("tailscale configured NATS account lookup failed when trying to connect %q: %w", tsAuthIdentifier, err)
			c.sendErr(fmt.Sprintf("server misconfiguration connecting you to account, sorry %q", tsAuthIdentifier))
			c.closeConnection(MissingAccount)
			return nil
		}
		s.Debugf("tailscale->account: %q placed in account %q", tsAuthIdentifier, acc.Name)
		c.registerWithAccount(acc)
	} else if tsnet.Options.MapUsers {
		user, ok := s.users[tsAuthIdentifier]
		if !ok {
			s.Debugf("tailscale->account: user %q not tied to any account when MapUsers", tsAuthIdentifier)
			c.sendErr(fmt.Sprintf("Sorry %q, no account grants you access", tsAuthIdentifier))
			c.closeConnection(AuthenticationViolation)
			return nil
		}
		if !c.connectionTypeAllowed(user.AllowedConnectionTypes) {
			s.Debugf("tailscale->account: tsuser %q nats-user %q connection type not allowed", tsAuthIdentifier, user.Username)
			c.sendErr("connection type not allowed for your user") // XXX is this compliant with disclosure policy?
			c.closeConnection(AuthenticationViolation)             // Is this the correct ClosedState?
			return nil
		}
		if user.Account != nil {
			s.Debugf("tailscale->account: tsuser %q -> nats-user %q in account %q", tsAuthIdentifier, user.Username, user.Account.Name)
		} else {
			s.Debugf("tailscale->account: tsuser %q -> nats-user %q without account", tsAuthIdentifier, user.Username)
		}
		c.RegisterUser(user)
	} else {
		s.Fatalf("BUG: unknown user->account disposition for tailscale connections")
	}

	c.mu.Lock()

	c.initClient()

	// I'm tempted to just not enable TLS, because the heuristics used to try
	// to handle automatic TLS-first-or-not seem unlikely to work well with a
	// slow VPN connection.  For now, let's say that since there's no
	// loadbalancing possible with tailscale in the way, we can just support
	// the old banner-then-upgrade flow.
	// I might regret not just making it TLS-first-always for Tailscale, but
	// ... we don't _need_ TLS and forced-TLS-first is more geared for a
	// mandatory TLS world.

	c.sendProtoNow(c.generateClientInfoJSON(info))

	c.mu.Unlock()

	s.mu.Lock()
	if !s.isRunning() || s.ldm {
		if s.isShuttingDown() {
			s.Debugf("dropping tailscale connection from %q because server is shutting down", tsAuthIdentifier)
			conn.Close()
		} else {
			s.Debugf("dropping tailscale connection from %q because server is LDM or not running", tsAuthIdentifier)
		}
		s.mu.Unlock()
		// XXX: why would we return c here?
		return nil
	}

	if opts.MaxConn > 0 && len(s.clients) >= opts.MaxConn {
		s.Debugf("dropping tailscale connection from %q because MaxConn (%v) exceeded", tsAuthIdentifier, opts.MaxConn)
		s.mu.Unlock()
		c.maxConnExceeded()
		return nil
	}
	s.clients[c.cid] = c
	s.mu.Unlock()

	c.mu.Lock()
	// FIXME TLS HERE

	if c.isClosed() {
		c.mu.Unlock()
		c.closeConnection(WriteError)
		return nil
	}

	// No auth offered at this time, but we might do something in the future
	// based on making accounts available based on group membership and then
	// the user just says which one they want and we pull ID from
	// whois.UserProfile.Groups[] rather than anything they send in-protocol
	// or anything we try to match based on identifiers.

	// Set the Ping timer. Will be reset once connect was received.
	c.setPingTimer()

	// Spin up the read loop.
	s.startGoRoutine(func() { c.readLoop(nil) })

	// Spin up the write loop.
	s.startGoRoutine(func() { c.writeLoop() })

	c.mu.Unlock()

	return c
}

/*
        if *addr == ":443" {
                ln = tls.NewListener(ln, &tls.Config{
                        GetCertificate: lc.GetCertificate,
                })
        }

	_ = &tls.Config{GetCertificate: tsnet.LocalClient.GetCertificate}
MapUsers

*/
