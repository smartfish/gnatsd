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
	"sync"
	"testing"
	"time"

	"github.com/nats-io/go-nats"
)

type waitForFunc func(s *Server) int

func waitFor(t *testing.T, s *Server, expected int, expectedStr string, timeout time.Duration, f waitForFunc) {
	t.Helper()

	var c int
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c = f(s)
		if c == expected {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("Expected %v %s, got %v", expected, expectedStr, c)
}

// Wait for the expected number of outbound gateways, or fails.
func waitForOutboundGateways(t *testing.T, s *Server, expected int, timeout time.Duration) {
	t.Helper()
	waitFor(t, s, expected, "outbound gateway(s)", timeout, func(s *Server) int { return s.numOutboundGateways() })
}

// Wait for the expected number of inbound gateways, or fails.
func waitForInboundGateways(t *testing.T, s *Server, expected int, timeout time.Duration) {
	t.Helper()
	waitFor(t, s, expected, "inbound gateway(s)", timeout, func(s *Server) int { return s.numInboundGateways() })
}

func waitForGatewayFailedConnect(t *testing.T, s *Server, gwName string, expectFailure bool, timeout time.Duration) {
	t.Helper()
	waitFor(t, s, 1, "failed connect", timeout, func(s *Server) int {
		var c int
		gw := s.getGatewayConfig(gwName)
		if gw != nil {
			c = gw.getFailedConnectCount()
		}
		if expectFailure && c > 0 {
			return 1
		} else if !expectFailure && c == 0 {
			return 1
		}
		return 0
	})
}

func testDefaultOptionsForGateway(name string) *Options {
	o := DefaultOptions()
	o.Gateway.Name = name
	o.Gateway.Host = "127.0.0.1"
	o.Gateway.Port = -1
	o.gatewaysSolicitDelay = 15 * time.Millisecond
	return o
}

func testGatewayOptionsFromToWithServers(t *testing.T, org, dst string, servers ...*Server) *Options {
	t.Helper()
	o := testDefaultOptionsForGateway(org)
	gw := &GatewayConnOpts{Name: dst}
	for _, s := range servers {
		us := fmt.Sprintf("nats://127.0.0.1:%d", s.GatewayAddr().Port)
		u, err := url.Parse(us)
		if err != nil {
			t.Fatalf("Error parsing url: %v", err)
		}
		gw.URLs = append(gw.URLs, u)
	}
	o.Gateway.Gateways = append(o.Gateway.Gateways, gw)
	return o
}

func testAddGatewayURLs(t *testing.T, o *Options, dst string, urls []string) {
	t.Helper()
	gw := &GatewayConnOpts{Name: dst}
	for _, us := range urls {
		u, err := url.Parse(us)
		if err != nil {
			t.Fatalf("Error parsing url: %v", err)
		}
		gw.URLs = append(gw.URLs, u)
	}
	o.Gateway.Gateways = append(o.Gateway.Gateways, gw)
}

func testGatewayOptionsFromToWithURLs(t *testing.T, org, dst string, urls []string) *Options {
	o := testDefaultOptionsForGateway(org)
	testAddGatewayURLs(t, o, dst, urls)
	return o
}

func testGatewayOptionsWithTLS(t *testing.T, name string) *Options {
	t.Helper()
	o := testDefaultOptionsForGateway(name)
	var (
		tc  = &TLSConfigOpts{}
		err error
	)
	if name == "A" {
		tc.CertFile = "../test/configs/certs/srva-cert.pem"
		tc.KeyFile = "../test/configs/certs/srva-key.pem"
	} else {
		tc.CertFile = "../test/configs/certs/srvb-cert.pem"
		tc.KeyFile = "../test/configs/certs/srvb-key.pem"
	}
	tc.CaFile = "../test/configs/certs/ca.pem"
	o.Gateway.TLSConfig, err = GenTLSConfig(tc)
	if err != nil {
		t.Fatalf("Error generating TLS config: %v", err)
	}
	o.Gateway.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
	o.Gateway.TLSConfig.RootCAs = o.Gateway.TLSConfig.ClientCAs
	o.Gateway.TLSTimeout = 2.0
	return o
}

func testGatewayOptionsFromToWithTLS(t *testing.T, org, dst string, urls []string) *Options {
	o := testGatewayOptionsWithTLS(t, org)
	testAddGatewayURLs(t, o, dst, urls)
	return o
}

func TestGatewayBasic(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, time.Second)

	// Stop s2 server
	s2.Shutdown()

	// gateway should go away
	waitForOutboundGateways(t, s1, 0, time.Second)
	waitForInboundGateways(t, s2, 0, time.Second)

	// Restart server
	s2 = RunServer(o2)
	defer s2.Shutdown()

	// gateway should reconnect
	waitForOutboundGateways(t, s1, 1, time.Second)
	waitForInboundGateways(t, s2, 1, time.Second)

	// Shutdown s1, remove the gateway from A to B and restart.
	s1.Shutdown()
	// When s2 detects the connection is closed, it will attempt
	// to reconnect once (even if the route is implicit). Wait
	// more than the dialTimeout before restarting the server.
	time.Sleep(1100 * time.Millisecond)
	// Restart s1 without gateway to B.
	o1.Gateway.Gateways = o1.Gateway.Gateways[:0]
	s1 = RunServer(o1)
	defer s1.Shutdown()

	// Make sure we wait more to be sure that s2 did not attempt
	// to reconnect to s1.
	time.Sleep(1500 * time.Millisecond)

	// s1 should not have any outbound nor inbound
	waitForOutboundGateways(t, s1, 0, time.Second)
	waitForInboundGateways(t, s1, 0, time.Second)

	// Same for s2
	waitForOutboundGateways(t, s2, 0, time.Second)
	waitForInboundGateways(t, s2, 0, time.Second)

	// Verify that s2 no longer has A gateway in its list
	if s2.getGatewayConfig("A") != nil {
		t.Fatal("Gateway A should have been removed from s2")
	}
}

func TestGatewaySolicitDelay(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	// Set the solicit delay to 0. This tests that server will use its
	// default value, currently set at 1 sec.
	o1.gatewaysSolicitDelay = 0
	start := time.Now()
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// After 500ms, check outbound gateway. Should not be there.
	time.Sleep(500 * time.Millisecond)
	if time.Since(start) < defaultSolicitGatewaysDelay {
		if s1.numOutboundGateways() > 0 {
			t.Fatalf("The outbound gateway was initiated sooner than expected (%v)", time.Since(start))
		}
	}
	// Ultimately, s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, 2*time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, 2*time.Second)

	s1.Shutdown()
	// Make sure that server can be shutdown while waiting
	// for that initial solicit delay
	o1.gatewaysSolicitDelay = 2 * time.Second
	s1 = RunServer(o1)
	start = time.Now()
	s1.Shutdown()
	if dur := time.Since(start); dur >= 2*time.Second {
		t.Fatalf("Looks like shutdown was delayed: %v", dur)
	}
}

func TestGatewaySolicitDelayWithImplicitOutbounds(t *testing.T) {
	// Cause a situation where A connects to B, and because of
	// delay of solicit gateways set on B, we want to make sure
	// that B does not end-up with 2 connections to A.
	o2 := testDefaultOptionsForGateway("B")
	o2.gatewaysSolicitDelay = 500 * time.Millisecond
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, 2*time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, 2*time.Second)
	// Wait for more than s2 solicit delay
	time.Sleep(750 * time.Millisecond)
	// The way we store outbound (map key'ed by gw name), we would
	// not know if we had created 2 (since the newer would replace
	// the older in the map). So use the client's cid to figure it out.
	// When A connects to B, the inbound should have cid==1, the
	// resulting outbound should be cid==2. Any higher and we probably
	// have the situation that more than 1 connection was created.
	s2.mu.Lock()
	c := s2.outGateways["A"]
	s2.mu.Unlock()
	c.mu.Lock()
	cid := c.cid
	c.mu.Unlock()
	if cid > 2 {
		t.Fatalf("Unexpected cid: %v", cid)
	}
}

func TestGatewaySolicitShutdown(t *testing.T) {
	var urls []string
	for i := 0; i < 50; i++ {
		u := fmt.Sprintf("nats://127.0.0.1:%d", 1234+i)
		urls = append(urls, u)
	}
	o1 := testGatewayOptionsFromToWithURLs(t, "A", "B", urls)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	time.Sleep(o1.gatewaysSolicitDelay + 10*time.Millisecond)

	start := time.Now()
	s1.Shutdown()
	if dur := time.Since(start); dur > time.Second {
		t.Fatalf("Took too long to shutdown: %v", dur)
	}
}

func TestGatewayListenError(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testDefaultOptionsForGateway("A")
	o1.Gateway.Port = s2.GatewayAddr().Port
	s1 := New(o1)
	defer s1.Shutdown()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		s1.Start()
		wg.Done()
	}()
	// We call Fatalf on listen error, but since there is no actual logger
	// associated, we just check that the listener is not created.
	time.Sleep(100 * time.Millisecond)
	addr := s1.GatewayAddr()
	if addr != nil {
		t.Fatal("Listener should not have been created")
	}
	s1.Shutdown()
	wg.Wait()
}

func TestGatewayAdvertise(t *testing.T) {
	o3 := testDefaultOptionsForGateway("C")
	s3 := RunServer(o3)
	defer s3.Shutdown()

	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	// Set the advertise so that this points to C
	o1.Gateway.Advertise = fmt.Sprintf("127.0.0.1:%d", s3.GatewayAddr().Port)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// We should have outbound from s1 to s2
	waitForOutboundGateways(t, s1, 1, time.Second)
	// But no inbound from s2
	waitForInboundGateways(t, s1, 0, time.Second)

	// And since B tries to connect to A but reaches C, it should fail to connect,
	// and without connect retries, stop trying. So no outbound for s2, and no
	// inbound/outbound for s3.
	waitForInboundGateways(t, s2, 1, time.Second)
	waitForOutboundGateways(t, s2, 0, time.Second)
	waitForInboundGateways(t, s3, 0, time.Second)
	waitForOutboundGateways(t, s3, 0, time.Second)
}

func TestGatewayAdvertiseErr(t *testing.T) {
	o1 := testDefaultOptionsForGateway("A")
	o1.Gateway.Advertise = "wrong:address"
	s1 := New(o1)
	defer s1.Shutdown()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		s1.Start()
		wg.Done()
	}()
	// We call Fatalf on listen error, but since there is no actual logger
	// associated, we just check that the listener is not created.
	time.Sleep(100 * time.Millisecond)
	addr := s1.GatewayAddr()
	if addr != nil {
		t.Fatal("Listener should not have been created")
	}
	s1.Shutdown()
	wg.Wait()
}

func TestGatewayAuth(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	o2.Gateway.Username = "me"
	o2.Gateway.Password = "pwd"
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithURLs(t, "A", "B", []string{fmt.Sprintf("nats://me:pwd@127.0.0.1:%d", s2.GatewayAddr().Port)})
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, time.Second)

	s2.Shutdown()
	s1.Shutdown()

	o2.Gateway.Username = "me"
	o2.Gateway.Password = "wrong"
	s2 = RunServer(o2)
	defer s2.Shutdown()

	s1 = RunServer(o1)
	defer s1.Shutdown()

	// Connection should fail...
	waitForGatewayFailedConnect(t, s1, "B", true, 2*time.Second)

	s2.Shutdown()
	s1.Shutdown()
	o2.Gateway.Username = "wrong"
	o2.Gateway.Password = "pwd"
	s2 = RunServer(o2)
	defer s2.Shutdown()

	s1 = RunServer(o1)
	defer s1.Shutdown()

	// Connection should fail...
	waitForGatewayFailedConnect(t, s1, "B", true, 2*time.Second)
}

func TestGatewayTLS(t *testing.T) {
	o2 := testGatewayOptionsWithTLS(t, "B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithTLS(t, "A", "B", []string{fmt.Sprintf("nats://127.0.0.1:%d", s2.GatewayAddr().Port)})
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, time.Second)

	// Stop s2 server
	s2.Shutdown()

	// gateway should go away
	waitForOutboundGateways(t, s1, 0, time.Second)
	waitForInboundGateways(t, s2, 0, time.Second)

	// Restart server
	s2 = RunServer(o2)
	defer s2.Shutdown()

	// gateway should reconnect
	waitForOutboundGateways(t, s1, 1, 2*time.Second)
	waitForInboundGateways(t, s2, 1, 2*time.Second)
}

func TestGatewayTLSErrors(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithTLS(t, "A", "B", []string{fmt.Sprintf("nats://127.0.0.1:%d", s2.ClusterAddr().Port)})
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// Expect s1 to have a failed to connect count > 0
	waitForGatewayFailedConnect(t, s1, "B", true, 2*time.Second)
}

func TestGatewayWrongDestination(t *testing.T) {
	// Start a server with a gateway named "C"
	o2 := testDefaultOptionsForGateway("C")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	// Configure a gateway to "B", but since we are connecting to "C"...
	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// we should not be able to connect.
	waitForGatewayFailedConnect(t, s1, "B", true, time.Second)

	// Shutdown s2 and correct the gateway name.
	// s1 should then connect ok and failed connect should be cleared.
	s2.Shutdown()
	o2.Gateway.Name = "B"
	s2 = RunServer(o2)
	defer s2.Shutdown()

	// At some point, the number of failed connect count should be reset to 0.
	waitForGatewayFailedConnect(t, s1, "B", false, 10*time.Second)
}

func TestGatewayConnectToWrongPort(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	// Configure a gateway to "B", but connect to the wrong port
	urls := []string{fmt.Sprintf("nats://127.0.0.1:%d", s2.Addr().(*net.TCPAddr).Port)}
	o1 := testGatewayOptionsFromToWithURLs(t, "A", "B", urls)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// we should not be able to connect.
	waitForGatewayFailedConnect(t, s1, "B", true, time.Second)

	s1.Shutdown()

	// Repeat with route port
	urls = []string{fmt.Sprintf("nats://127.0.0.1:%d", s2.ClusterAddr().Port)}
	o1 = testGatewayOptionsFromToWithURLs(t, "A", "B", urls)
	s1 = RunServer(o1)
	defer s1.Shutdown()

	// we should not be able to connect.
	waitForGatewayFailedConnect(t, s1, "B", true, time.Second)

	s1.Shutdown()

	// Now have a client connect to s2's gateway port.
	nc, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", s2.GatewayAddr().Port))
	if err == nil {
		nc.Close()
		t.Fatal("Expected error, got none")
	}
}

func TestGatewayCreateImplicit(t *testing.T) {
	// Create a regular cluster of 2 servers
	o2 := testDefaultOptionsForGateway("B")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o3 := testDefaultOptionsForGateway("B")
	o3.Routes = RoutesFromStr(fmt.Sprintf("nats://127.0.0.1:%d", s2.ClusterAddr().Port))
	s3 := RunServer(o3)
	defer s3.Shutdown()

	checkClusterFormed(t, s2, s3)

	// Now start s1 that creates a Gateway connection to s2 or s3
	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2, s3)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// We should have an outbound gateway connection on ALL servers.
	waitForOutboundGateways(t, s1, 1, 2*time.Second)
	waitForOutboundGateways(t, s2, 1, 2*time.Second)
	waitForOutboundGateways(t, s3, 1, 2*time.Second)

	// Server s1 must have 2 inbound ones
	waitForInboundGateways(t, s1, 2, 2*time.Second)

	// However, s1 may have created the outbound to s2 or s3. It is possible that
	// either s2 or s3 does not an inbound connection.
	s2Inbound := s2.numInboundGateways()
	s3Inbound := s3.numInboundGateways()
	if (s2Inbound == 1 && s3Inbound != 0) || (s3Inbound == 1 && s2Inbound != 0) {
		t.Fatalf("Unexpected inbound for s2/s3: %v/%v", s2Inbound, s3Inbound)
	}
}

func TestGatewayImplicitReconnect(t *testing.T) {
	o2 := testDefaultOptionsForGateway("B")
	o2.Gateway.ConnectRetries = 5
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithServers(t, "A", "B", s2)
	s1 := RunServer(o1)
	defer s1.Shutdown()

	// s1 should have an outbound gateway to s2.
	waitForOutboundGateways(t, s1, 1, time.Second)
	// s2 should have an inbound gateway
	waitForInboundGateways(t, s2, 1, time.Second)

	// Shutdown s1, remove the gateway from A to B and restart.
	s1.Shutdown()
	o1.Gateway.Gateways = o1.Gateway.Gateways[:0]
	s1 = RunServer(o1)
	defer s1.Shutdown()

	// Wait enough so that s2 has a chance to reconnect
	time.Sleep(1500 * time.Millisecond)

	// s1 should have both outbound and inbound to s2
	waitForOutboundGateways(t, s1, 1, time.Second)
	waitForInboundGateways(t, s1, 1, time.Second)

	// Same for s2
	waitForOutboundGateways(t, s2, 1, time.Second)
	waitForInboundGateways(t, s2, 1, time.Second)

	// Verify that s2 still has "A" in its gateway config
	if s2.getGatewayConfig("A") == nil {
		t.Fatal("Gateway A should be in s2")
	}
}

func TestGatewayURLsFromClusterSentInINFO(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to setup listen port: %v", err)
	}
	defer l.Close()

	ch := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			ch <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		br := bufio.NewReaderSize(c, len(buf))
		// consume CONNECT
		if _, _, err := br.ReadLine(); err != nil {
			ch <- err
			return
		}
		// This is INFO
		proto, _, err := br.ReadLine()
		if err != nil {
			ch <- err
			return
		}
		// Strip `INFO `
		info := &Info{}
		if err := json.Unmarshal(proto[5:], info); err != nil {
			ch <- err
			return
		}
		if len(info.GatewayURLs) != 3 {
			ch <- fmt.Errorf("Unexpected gateway URLs: %v", info.GatewayURLs)
			return
		}
		// We are good.
		ch <- nil
	}()

	// Create a cluster of 3 servers
	o3 := testDefaultOptionsForGateway("A")
	s3 := RunServer(o3)
	defer s3.Shutdown()

	o2 := testDefaultOptionsForGateway("A")
	s2 := RunServer(o2)
	defer s2.Shutdown()

	o1 := testGatewayOptionsFromToWithURLs(t, "A", "B", []string{fmt.Sprintf("nats://127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)})
	// Add delay to make sure that cluster forms before soliciting gateways
	o1.gatewaysSolicitDelay = time.Second
	o1.Routes = RoutesFromStr(fmt.Sprintf("nats://127.0.0.1:%d,nats://127.0.0.1:%d", s3.ClusterAddr().Port, s2.ClusterAddr().Port))
	s1 := RunServer(o1)
	defer s1.Shutdown()

	checkClusterFormed(t, s1, s2, s3)

	// Wait for more than it takes to start soliciting gateways.
	time.Sleep(1500 * time.Millisecond)

	select {
	case e := <-ch:
		if e != nil {
			t.Fatalf(e.Error())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timeout waiting for test to complete")
	}
}
