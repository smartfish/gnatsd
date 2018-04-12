// Copyright 2018 The NATS Authors
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
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/gnatsd/util"
)

const (
	gatewayMaxWaitBetweenConnect = 30 * time.Second
	defaultSolicitGatewaysDelay  = time.Second
)

// For now, this is just a sync Map.
type configGateways = sync.Map

type cfgGateway struct {
	sync.RWMutex
	*GatewayConnOpts
	urls          map[*url.URL]struct{}
	nextConnect   time.Time
	failedConnect int
	implicit      bool
}

// Ensure that gateway is properly configured.
func validateGatewayOptions(o *Options) error {
	if o.Gateway.Name == "" && o.Gateway.Port == 0 {
		return nil
	}
	if o.Gateway.Name == "" {
		return fmt.Errorf("gateway has no name")
	}
	if o.Gateway.Port == 0 {
		return fmt.Errorf("gateway %q has no port specified (select -1 for random port)", o.Gateway.Name)
	}
	for i, g := range o.Gateway.Gateways {
		if g.Name == "" {
			return fmt.Errorf("gateway in the list %d has no name", i)
		}
		if len(g.URLs) == 0 {
			return fmt.Errorf("gateway %q has no URL", g.Name)
		}
	}
	return nil
}

func (s *Server) setupGatewaysConfig(gws []*GatewayConnOpts) {
	for _, gwOpt := range gws {
		gw := &cfgGateway{
			GatewayConnOpts: gwOpt,
			urls:            make(map[*url.URL]struct{}, len(gwOpt.URLs)),
		}
		for _, u := range gwOpt.URLs {
			gw.urls[u] = struct{}{}
		}
		s.cfgGateways.Store(gwOpt.Name, gw)
	}
}

func (s *Server) startGateways() {
	// Spin up the accept loop
	ch := make(chan struct{})
	go s.gatewayAcceptLoop(ch)
	<-ch

	// Delay start of creation of gateways to give a chance
	// to the local cluster to form.
	s.startGoRoutine(func() {
		defer s.grWG.Done()

		dur := s.getOpts().gatewaysSolicitDelay
		if dur == 0 {
			dur = defaultSolicitGatewaysDelay
		}

		select {
		case <-time.After(dur):
			s.solicitGateways(s.cfgGateways)
		case <-s.quitCh:
			return
		}
	})
}

func (s *Server) gatewayAcceptLoop(ch chan struct{}) {
	defer func() {
		if ch != nil {
			close(ch)
		}
	}()

	// Snapshot server options.
	opts := s.getOpts()

	port := opts.Gateway.Port
	if port == -1 {
		port = 0
	}

	hp := net.JoinHostPort(opts.Gateway.Host, strconv.Itoa(port))
	l, e := net.Listen("tcp", hp)
	if e != nil {
		s.Fatalf("Error listening on gateway port: %d - %v", opts.Gateway.Port, e)
		return
	}
	s.Noticef("Listening for gateways connections on %s",
		net.JoinHostPort(opts.Gateway.Host, strconv.Itoa(l.Addr().(*net.TCPAddr).Port)))

	s.mu.Lock()
	tlsReq := opts.Gateway.TLSConfig != nil
	authRequired := opts.Gateway.Username != ""
	info := Info{
		ID:           s.info.ID,
		Version:      s.info.Version,
		AuthRequired: authRequired,
		TLSRequired:  tlsReq,
		TLSVerify:    tlsReq,
		MaxPayload:   s.info.MaxPayload,
		Gateway:      opts.Gateway.Name,
	}
	// If we have selected a random port...
	if port == 0 {
		// Write resolved port back to options.
		opts.Gateway.Port = l.Addr().(*net.TCPAddr).Port
	}
	// Keep track of actual listen port. This will be needed in case of
	// config reload.
	s.gatewayActualPort = opts.Gateway.Port
	s.gatewayInfo = info
	// Possibly override Host/Port based on Gateway.Advertise
	if err := s.setGatewayInfoHostPort(&s.gatewayInfo, opts); err != nil {
		s.Fatalf("Error setting gateway INFO with Gateway.Advertise value of %s, err=%v", opts.Gateway.Advertise, err)
		l.Close()
		s.mu.Unlock()
		return
	}
	// Setup state that can enable shutdown
	s.gatewayListener = l
	s.mu.Unlock()

	// Let them know we are up
	close(ch)
	ch = nil

	tmpDelay := ACCEPT_MIN_SLEEP

	for s.isRunning() {
		conn, err := l.Accept()
		if err != nil {
			tmpDelay = s.acceptError("Gateway", err, tmpDelay)
			continue
		}
		tmpDelay = ACCEPT_MIN_SLEEP
		s.startGoRoutine(func() {
			s.createGateway(nil, nil, conn)
			s.grWG.Done()
		})
	}
	s.Debugf("Gateway accept loop exiting..")
	s.done <- true
}

// Similar to setInfoHostPortAndGenerateJSON, but for gatewayInfo.
func (s *Server) setGatewayInfoHostPort(info *Info, o *Options) error {
	if o.Gateway.Advertise != "" {
		advHost, advPort, err := parseHostPort(o.Gateway.Advertise, o.Gateway.Port)
		if err != nil {
			return err
		}
		info.Host = advHost
		info.Port = advPort
	} else {
		info.Host = o.Gateway.Host
		info.Port = o.Gateway.Port
	}
	s.removeGatewayURL(s.gatewayURL)
	s.gatewayURL = fmt.Sprintf("%s:%d", info.Host, info.Port)
	s.addGatewayURL(s.gatewayURL)
	info.GatewayURL = s.gatewayURL
	// (re)generate the gatewayInfoJSON byte array
	s.generateGatewayInfoJSON(info)
	return nil
}

func (s *Server) generateGatewayInfoJSON(info *Info) error {
	b, err := json.Marshal(info)
	if err != nil {
		return err
	}
	s.gatewayInfoJSON = []byte(fmt.Sprintf(InfoProto, b))
	return nil
}

func (s *Server) solicitGateways(gws *configGateways) {
	gws.Range(func(k, v interface{}) bool {
		gw := v.(*cfgGateway)
		// Since we delay the creation of gateways, it is
		// possible that server starts to receive inbound from
		// other clusters and in turn create outbounds. So here
		// we create only the ones that are configured.
		if !gw.isImplicit() {
			s.startGoRoutine(func() {
				s.solicitGateway(gw)
				s.grWG.Done()
			})
		}
		return true
	})
}

// This function will loop trying to connect to any URL attached
// to the given Gateway. It will return once a connection has been created.
func (s *Server) solicitGateway(gw *cfgGateway) {
	var (
		opts       = s.getOpts()
		isImplicit = gw.isImplicit()
		attempts   int
	)
	for s.isRunning() && len(gw.urls) > 0 {
		// This is used to prevent rapid connect attempts if there was
		// an error during the createGateway() call, or if the remote rejected
		// us for any reason.
		nextConnect := gw.getNextConnect()
		if time.Now().After(nextConnect) {
			// Iteration is random
			for u := range gw.urls {
				s.Debugf("Trying to connect to gateway %q at %s", gw.Name, u.Host)
				conn, err := net.DialTimeout("tcp", u.Host, DEFAULT_ROUTE_DIAL)
				if err != nil {
					s.Errorf("Error trying to connect to gateway: %v", err)
					select {
					case <-s.quitCh:
						return
					default:
						continue
					}
				}
				// We could connect, create the gateway connection and return.
				s.createGateway(gw, u, conn)
				return
			}
		}
		if isImplicit {
			attempts++
			if opts.Gateway.ConnectRetries == 0 || attempts > opts.Gateway.ConnectRetries {
				s.cfgGateways.Delete(gw.Name)
				return
			}
		}
		dur := time.Until(nextConnect)
		if dur < DEFAULT_ROUTE_CONNECT {
			dur = DEFAULT_ROUTE_CONNECT
		}
		select {
		case <-s.quitCh:
			return
		case <-time.After(dur):
		}
	}
}

func (s *Server) createGateway(gw *cfgGateway, url *url.URL, conn net.Conn) {
	// Snapshot server options.
	opts := s.getOpts()

	c := &client{srv: s, nc: conn, typ: GATEWAY}

	// Are we creating the gateway based on the configuration
	solicit := gw != nil

	// Perform some initialization under the client lock
	c.mu.Lock()
	c.initClient()
	if solicit {
		c.flags.set(outboundGateway)
		c.opts = clientOpts{Name: gw.Name}
		c.Noticef("Creating gateway connection to %q", gw.Name)
	} else {
		c.flags.set(inboundGateway)
		c.Noticef("Gateway connection created")
	}
	cid := c.cid
	c.mu.Unlock()

	// Generate INFO to send and register this gateway
	s.mu.Lock()
	tlsRequired := opts.Gateway.TLSConfig != nil
	myGatewayName := opts.Gateway.Name

	info := s.gatewayInfo
	info.GatewayURLs = s.getGatewayURLs()
	b, _ := json.Marshal(info)
	infoJSON := []byte(fmt.Sprintf(InfoProto, b))
	s.mu.Unlock()

	c.mu.Lock()

	// Check for TLS
	if tlsRequired {
		// Copy off the config to add in ServerName if we
		tlsConfig := util.CloneTLSConfig(opts.Gateway.TLSConfig)

		// If we solicited, we will act like the client, otherwise the server.
		if solicit {
			c.Debugf("Starting TLS gateway client handshake")
			// Specify the ServerName we are expecting.
			host, _, _ := net.SplitHostPort(url.Host)
			tlsConfig.ServerName = host
			c.nc = tls.Client(c.nc, tlsConfig)
		} else {
			c.Debugf("Starting TLS gateway server handshake")
			c.nc = tls.Server(c.nc, tlsConfig)
		}

		conn := c.nc.(*tls.Conn)

		// Setup the timeout
		ttl := secondsToDuration(opts.Gateway.TLSTimeout)
		time.AfterFunc(ttl, func() { tlsTimeout(c, conn) })
		conn.SetReadDeadline(time.Now().Add(ttl))

		c.mu.Unlock()
		if err := conn.Handshake(); err != nil {
			c.Errorf("TLS gateway handshake error: %v", err)
			c.sendErr("Secure Connection - TLS Required")
			gw.processConnectError()
			c.closeConnection()
			return
		}
		// Reset the read deadline
		conn.SetReadDeadline(time.Time{})

		// Re-Grab lock
		c.mu.Lock()

		// Verify that the connection did not go away while we released the lock.
		if c.nc == nil {
			c.mu.Unlock()
			return
		}

		// Rewrap bw
		c.bw = bufio.NewWriterSize(c.nc, startBufSize)
	}

	// Do final client initialization

	// Set the Ping timer
	c.setPingTimer()

	// Register in temp map for now until gateway properly registered
	// in out or in gateways.
	if !s.addToTempClients(cid, c) {
		c.mu.Unlock()
		c.closeConnection()
		return
	}

	// Spin up the read loop.
	s.startGoRoutine(func() { c.readLoop() })

	if tlsRequired {
		c.Debugf("TLS handshake complete")
		cs := c.nc.(*tls.Conn).ConnectionState()
		c.Debugf("TLS version %s, cipher suite %s", tlsVersion(cs.Version), tlsCipher(cs.CipherSuite))
	}

	if solicit {
		// Send our CONNECT protocol.
		c.Debugf("Gateway connect protocol sent")
		c.sendGatewayConnect(url, tlsRequired, myGatewayName, gw.Name)
	}

	// Send our info to the other side.
	c.sendInfo(infoJSON)

	c.mu.Unlock()
}

func (c *client) sendGatewayConnect(url *url.URL, tlsRequired bool, gwNameOrg, gwNameDst string) {
	var user, pass string
	if userInfo := url.User; userInfo != nil {
		user = userInfo.Username()
		pass, _ = userInfo.Password()
	}
	cinfo := connectInfo{
		Verbose:    false,
		Pedantic:   false,
		User:       user,
		Pass:       pass,
		TLS:        tlsRequired,
		Name:       c.srv.info.ID,
		GatewayOrg: gwNameOrg,
		GatewayDst: gwNameDst,
	}
	b, err := json.Marshal(cinfo)
	if err != nil {
		panic(err)
	}
	c.sendProto([]byte(fmt.Sprintf(ConProto, b)), true)
}

func (c *client) processGatewayConnect(arg []byte) error {
	proto := &connectInfo{}
	if err := json.Unmarshal(arg, proto); err != nil {
		return err
	}

	s := c.srv
	s.mu.Lock()
	myGatewayName := s.getOpts().Gateway.Name
	s.mu.Unlock()

	// Coming from a client or a route, reject
	if proto.GatewayDst == "" {
		errTxt := ErrClientOrRouteConnectedToGatewayPort.Error()
		c.Errorf(errTxt)
		c.sendErr(errTxt)
		c.closeConnection()
		return errAlreadyHandled
	}
	if myGatewayName != proto.GatewayDst {
		errTxt := fmt.Sprintf("Connection from %q to %q rejected, wrong destination", proto.GatewayOrg, proto.GatewayDst)
		c.Errorf(errTxt)
		c.sendErr(errTxt)
		c.closeConnection()
		return errAlreadyHandled
	}

	c.Noticef("Gateway connection from %q accepted", proto.GatewayOrg)

	return nil
}

func (c *client) processGatewayInfo(arg []byte, info *Info) {
	isInbound := false

	c.mu.Lock()
	s := c.srv
	cid := c.cid
	if c.flags.isSet(outboundGateway) {
		// Check content of INFO for fields indicating that it comes from a gateway.
		// If we incorrectly connect to the wrong port (client or route), we won't
		// have the Gateway field set.
		if info.Gateway == "" {
			gw := s.getGatewayConfig(c.opts.Name)
			c.mu.Unlock()
			gw.processConnectError()
			errTxt := fmt.Sprintf("Attempt to connect to Gateway %q using wrong port", gw.Name)
			s.Errorf(errTxt)
			c.sendErr(errTxt)
			c.closeConnection()
			return
		}
		// Send a PING (it may have been sent already when setting the PingTimer
		// if the interval is very low). It does not matter, we just want to
		// receive a PONG for a confirmation that there was no connect error sent
		// from the other side.
		c.traceOutOp("PING", nil)
		c.sendProto([]byte("PING\r\n"), true)
	} else {
		isInbound = true
		c.opts.Name = info.Gateway
	}
	c.mu.Unlock()

	if isInbound {
		s.mu.Lock()
		s.inGateways[cid] = c
		s.mu.Unlock()

		// Now that it is registered, we can remove from temp map.
		s.removeFromTempClients(cid)

		// Initiate outbound connection. This function will behave correctly if
		// we have already one.
		s.processImplicitGateway(info)
	}

	// Flood local cluster with information about this gateway.
	// Servers in this cluster will ensure that they have (or otherwise create)
	// an outbound connection to this gateway.
	s.forwardNewGatewayToLocalCluster(arg)
}

func (s *Server) forwardNewGatewayToLocalCluster(infoAsBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	infoJSON := []byte(fmt.Sprintf(InfoProto, infoAsBytes))

	for _, r := range s.routes {
		r.mu.Lock()
		r.sendInfo(infoJSON)
		r.mu.Unlock()
	}
}

func (c *client) processGatewayPong() {
	c.mu.Lock()
	c.pout = 0
	var (
		register bool
		cid      = c.cid
		s        = c.srv
		gwName   = c.opts.Name
	)
	// In the gateway case, firstPongSent means that the remote sent us the first PONG
	if c.flags.setIfNotSet(firstPongSent) {
		gw := c.srv.getGatewayConfig(gwName)
		if gw != nil {
			gw.resetFailedConnectCount()
		}
		register = s != nil && c.flags.isSet(outboundGateway)
		c.Noticef("Gateway connection to %q created", gwName)
	}
	c.mu.Unlock()

	if register {
		s.mu.Lock()
		s.outGateways[gwName] = c
		s.mu.Unlock()
		// Now that the outbound gateway is registered, we can remove from temp map.
		s.removeFromTempClients(cid)
	}
}

func (c *client) processGatewayErr(_ string) {
	// Bump the nextConnect time...
	c.mu.Lock()
	gwName := c.opts.Name
	c.mu.Unlock()
	gw := c.srv.getGatewayConfig(gwName)
	if gw != nil {
		gw.processConnectError()
	}
}

func (s *Server) processImplicitGateway(info *Info) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	// Name of the gateway to connect to is the Info.Gateway field.
	gwName := info.Gateway
	// Check if we already have this config, and if so, we are done
	gwCfg := s.getGatewayConfig(gwName)
	if gwCfg != nil {
		return
	}
	gwCfg = &cfgGateway{
		GatewayConnOpts: &GatewayConnOpts{Name: gwName},
		urls:            make(map[*url.URL]struct{}, len(info.GatewayURLs)),
		implicit:        true,
	}
	for _, us := range info.GatewayURLs {
		u, err := url.Parse(fmt.Sprintf("nats://%s", us))
		if err != nil {
			s.Errorf("Error parsing url %q for gateway %q: %v", us, gwName, err)
		} else {
			gwCfg.urls[u] = struct{}{}
		}
	}
	// If there is no URL, we can't proceed.
	if len(gwCfg.urls) == 0 {
		return
	}
	s.cfgGateways.Store(gwName, gwCfg)
	s.startGoRoutine(func() {
		s.solicitGateway(gwCfg)
		s.grWG.Done()
	})
}

func (s *Server) numOutboundGateways() int {
	s.mu.Lock()
	n := len(s.outGateways)
	s.mu.Unlock()
	return n
}

func (s *Server) numInboundGateways() int {
	s.mu.Lock()
	n := len(s.inGateways)
	s.mu.Unlock()
	return n
}

// Returns the GatewayOpts (if any) that has the given `name`
func (s *Server) getGatewayConfig(name string) *cfgGateway {
	gwi, ok := s.cfgGateways.Load(name)
	if !ok {
		return nil
	}
	return gwi.(*cfgGateway)
}

func (gc *cfgGateway) processConnectError() {
	gc.Lock()
	gc.failedConnect++
	extra := time.Duration(2*(gc.failedConnect-1)) * time.Second
	if extra > gatewayMaxWaitBetweenConnect {
		extra = gatewayMaxWaitBetweenConnect
	}
	gc.nextConnect = time.Now().Add(extra)
	gc.Unlock()
}

func (gc *cfgGateway) resetFailedConnectCount() {
	gc.Lock()
	gc.failedConnect = 0
	gc.Unlock()
}

func (gc *cfgGateway) getFailedConnectCount() int {
	gc.RLock()
	fc := gc.failedConnect
	gc.RUnlock()
	return fc
}

func (gc *cfgGateway) getNextConnect() time.Time {
	gc.RLock()
	nc := gc.nextConnect
	gc.RUnlock()
	return nc
}

func (gc *cfgGateway) isImplicit() bool {
	gc.RLock()
	ii := gc.implicit
	gc.RUnlock()
	return ii
}

// Adds this URL to the set of Gateway URLs
// Server lock held on entry
func (s *Server) addGatewayURL(urlStr string) {
	s.gatewayURLs[urlStr] = struct{}{}
}

// Remove this URL from the set of gateway URLs
// Server lock held on entry
func (s *Server) removeGatewayURL(urlStr string) {
	delete(s.gatewayURLs, urlStr)
}

// Returns the set of gateway URLs as an array.
// Server lock held on entry
func (s *Server) getGatewayURLs() []string {
	a := make([]string, 0, len(s.gatewayURLs))
	for u := range s.gatewayURLs {
		a = append(a, u)
	}
	return a
}

// GatewayAddr returns the net.Addr object for the gateway listener.
func (s *Server) GatewayAddr() *net.TCPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gatewayListener == nil {
		return nil
	}
	return s.gatewayListener.Addr().(*net.TCPAddr)
}
