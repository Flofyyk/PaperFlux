package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"universal-bypass-tool/socks5"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/relayv2"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"
)

var (
	globalDocUrl string
	maxToken     string
	maxUid       string
	profileID    string
	profileToken string
)

func main() {
	//os.Setenv("GODEBUG", "netdns=go")
	fmt.Print("written by p1neappleXpress\n")

	exitNode := flag.Bool("exit-node", false, "Run as exit node")
	client := flag.Bool("client", false, "Run as client")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	socksAddr := flag.String("socks5", ":1080", "SOCKS5 address")
	tunFdSock := flag.String("tun-fd-sock", "", "abstract Unix socket for an Android VpnService TUN descriptor")
	packetSock := flag.String("packet-sock", "", "TCP packet bridge address for isolated Android worker")
	clientIPFlag := flag.String("client-ip", "10.10.10.2", "Virtual IPv4 address for this Android worker")
	exitModeFlag := flag.String("mode", "raw", "Exit-node mode: raw or proxy")
	transportType := flag.String("transport", "yandex", "Transport type (yandex, google, custom)")
	documentURLs := flag.String("urls", "", "Comma-separated Yandex Docs URLs for parallel document lanes")
	relayURL := flag.String("relay-url", "", "V2 relay WebSocket URL")
	relayToken := flag.String("relay-token", "", "V2 relay bearer token")
	relayUser := flag.Uint64("relay-user", 0, "V2 relay user id")
	relaySession := flag.String("relay-session", "", "V2 relay session id")
	flag.StringVar(&globalDocUrl, "url", "http://#", "Document URL. If u use Yandex.Docs transport")
	flag.StringVar(&maxToken, "maxToken", "", "MAX call user id. If u use MAX transport")
	flag.StringVar(&maxUid, "maxUid", "", "MAX Web token. If u use MAX transport")
	flag.StringVar(&profileID, "profile-id", "", "PaperFlux profile id")
	flag.StringVar(&profileToken, "profile-token", "", "PaperFlux profile access token")
	flag.Parse()

	if !*exitNode && !*client {
		flag.Usage()
		os.Exit(1)
	}

	if *debug {
		utils.EnableDebug()
	}
	exitMode, err := tunnel.ParseExitMode(*exitModeFlag)
	if err != nil {
		log.Fatalf("--mode: %v", err)
	}
	clientIP := [4]byte{10, 10, 10, 2}
	if parsed := net.ParseIP(*clientIPFlag).To4(); parsed != nil {
		copy(clientIP[:], parsed)
	} else {
		log.Fatalf("Invalid --client-ip %q", *clientIPFlag)
	}
	if *client && (*tunFdSock != "" || *packetSock != "") {
		configureAndroidResolver()
	}

	log.Printf("=== Universal Bypass Tool ===")
	log.Printf("Mode: %s", map[bool]string{true: "EXIT NODE", false: "CLIENT"}[*exitNode])
	log.Printf("Transport: %s", *transportType)
	if profileID != "" {
		log.Printf("PaperFlux profile identity: %s", profileID)
	}

	config := transport.DefaultConfig()
	var trans transport.Transport

	switch *transportType {
	case "yandex":
		urls := []string{globalDocUrl}
		if strings.TrimSpace(*documentURLs) != "" {
			urls = strings.Split(*documentURLs, ",")
		}
		lanes := make([]transport.Transport, 0, len(urls))
		for _, raw := range urls {
			url := strings.TrimSpace(raw)
			if url == "" {
				continue
			}
			// Yandex transport performs batching first and lets WebSocket
			// permessage-deflate compress the complete JSON/Base64 frame. Do not
			// wrap individual TUN packets in the legacy LZ4 transport layer.
			role := "client"
			if *exitNode {
				role = "exit"
			}
			lanes = append(lanes, yandex.NewYandexDocsTransport(url, config, profileID, profileToken, role))
		}
		if len(lanes) == 0 {
			log.Fatal("No Yandex document URLs configured")
		}
		if len(lanes) == 1 {
			trans = lanes[0]
		} else {
			// A multi transport emits one aggregate statistics stream.  Suppress
			// independent lane streams: their counter resets cannot be interpreted
			// correctly by a single Android VPN notification.
			for _, lane := range lanes {
				if yandexLane, ok := lane.(*yandex.YandexDocsTransport); ok {
					yandexLane.SetStatsLogging(false)
				}
			}
			trans = transport.NewMultiTransport(lanes, config)
			// Each document lane is already a WebSocket over TCP, therefore it
			// provides ordered, acknowledged delivery while that session is alive.
			// A second ACK/retry layer across two independently rotating documents
			// caused an ACK feedback queue on Android and reduced throughput. The
			// Yandex transport owns bounded replay across a session rotation instead.
			log.Printf("Yandex parallel document lanes: %d", len(lanes))
		}
	case "oneme":
		uidint, _ := strconv.ParseInt(maxUid, 10, 64)
		trans = transport.NewCompressedTransport(oneme.NewOneMeTransport(*exitNode, maxToken, uidint, config))
	case "relayv2":
		role := "client"
		if *exitNode {
			role = "exit"
		}
		var err error
		trans, err = relayv2.New(relayv2.Config{URL: *relayURL, Token: *relayToken, UserID: *relayUser, Session: *relaySession, Role: role}, config)
		if err != nil {
			log.Fatalf("Relay V2 configuration: %v", err)
		}
	default:
		log.Fatalf("Unknown transport type: %s", *transportType)
	}

	if err := trans.Start(); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}

	if *client && *tunFdSock != "" {
		// Do not accept Android's TUN descriptor until the document transport is
		// authenticated. Otherwise Android immediately sends background traffic
		// into a queue with no exit path, producing artificial packet drops.
		log.Printf("Waiting for Yandex transport authentication before TUN attach")
		for !trans.IsConnected() {
			time.Sleep(100 * time.Millisecond)
		}
		log.Printf("Yandex transport authenticated; waiting for TUN descriptor")
		log.Printf("Running as Android VPN CLIENT (waiting for TUN descriptor)")
		tunFile, err := recvTunFD(*tunFdSock)
		if err != nil {
			log.Fatalf("Failed to receive Android TUN descriptor: %v", err)
		}
		defer tunFile.Close()
		// Terminate Android TCP flows in a userland netstack and feed them into
		// the existing OpenFlux SOCKS5 client. Sending raw IP packets directly
		// to the exit node makes Android reject the returned SYN-ACK.
		tcpTunnel := tunnel.NewTCPTunnelWithClientIP(trans, false, clientIP)
		go tcpTunnel.RunHealthChecks()
		server := socks5.NewSOCKS5Server("127.0.0.1:1080", tcpTunnel)
		go func() {
			if err := server.Start(); err != nil {
				log.Printf("Android SOCKS5 server stopped: %v", err)
			}
		}()
		select {
		case <-server.Ready():
			log.Printf("Android SOCKS5 listener ready")
		case <-time.After(2 * time.Second):
			log.Fatalf("Android SOCKS5 listener did not start")
		}
		if err := runTun2Socks(tunFile, 1400, "127.0.0.1:1080", tcpTunnel); err != nil {
			log.Fatalf("tun2socks stopped: %v", err)
		}
		return
	}
	if *client && *packetSock != "" {
		log.Printf("Yandex transport authenticated; connecting packet bridge %s", *packetSock)
		bridge, err := connectPacketBridge(*packetSock)
		if err != nil {
			log.Fatalf("Failed to connect packet bridge: %v", err)
		}
		defer bridge.Close()
		log.Printf("Running as isolated Android VPN worker")
		tcpTunnel := tunnel.NewTCPTunnelWithClientIP(trans, false, clientIP)
		workerSocks := *socksAddr
		go func() {
			server := socks5.NewSOCKS5Server(workerSocks, tcpTunnel)
			if err := server.Start(); err != nil {
				log.Printf("Android worker SOCKS5 stopped: %v", err)
			}
		}()
		if err := runTun2Socks(bridge, 1400, workerSocks, tcpTunnel); err != nil {
			log.Fatalf("packet bridge stopped: %v", err)
		}
		return
	}

	tun := tunnel.NewTCPTunnelWithClientIPMode(trans, *exitNode, clientIP, exitMode)

	if *exitNode {
		log.Printf("Running as EXIT NODE (%s mode)", exitMode)
		if exitMode == tunnel.ExitModeRaw {
			log.Printf("! Raw mode requires an OUTPUT RST rule scoped to the exit-node source address; see docs/DEPLOYMENT.md")
		}
		select {}
	} else {
		log.Printf("Running as CLIENT (SOCKS5 on %s)", *socksAddr)
		socks5Server := socks5.NewSOCKS5Server(*socksAddr, tun)
		log.Fatal(socks5Server.Start())
	}
}
