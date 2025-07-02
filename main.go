package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jcrussell/discovery/src/pkg/p0f"
)

// MockPacket implements the p0f.Packet interface for testing
type MockPacket struct {
	ipLayer  gopacket.Layer
	tcpLayer *layers.TCP
}

func (m *MockPacket) IP() gopacket.Layer {
	return m.ipLayer
}

func (m *MockPacket) TCP() *layers.TCP {
	return m.tcpLayer
}

func main() {
	fmt.Println("=== P0F Package Testing Suite ===")
	fmt.Println()

	// Test 1: Parse TCP Signature
	testParseTCPSignature()

	// Test 2: Create Mock Packet and TCP SYN
	testMockPacketAndTCPSyn()

	// Test 3: Test Constants and Variables
	testConstantsAndVariables()

	// Test 4: Test Signature Matching
	testSignatureMatching()

	// Test 5: Run advanced tests
	fmt.Println("=== Running Advanced Tests ===")
	runAdvancedTests()

	// Test 6: Run working signatures demo
	fmt.Println()
	runWorkingSignatureDemo()

	// Test 7: Test with real pcap data
	fmt.Println()
	testWithPcapFile()

	// Test 8: Test P0f Database Parser
	testP0fParser()

	// Test 9: Enhanced pcap analysis with database - TODO: Implement
	// testEnhancedPcapAnalysis()

	// Test 10: Comprehensive P0f Database Test
	testComprehensiveP0fDatabase()
}

func runAdvancedTests() {
	testRealWorldSignatures()
	testQuirksInDetail()
	testPerformanceCharacteristics()
}

func testRealWorldSignatures() {
	fmt.Println("--- Real World Signature Tests (Using P0f Database) ---")

	// Load the p0f.fp database
	parser := NewP0fParser()
	db, err := parser.ParseFile("p0f.fp")
	if err != nil {
		fmt.Printf("  ❌ Error parsing p0f.fp: %v\n", err)
		return
	}

	fmt.Printf("Testing with %d signatures from p0f.fp database\n", len(db.TCPRequest))

	// Test with real signatures from the database
	testSignatures := []struct {
		Expected string
		Pattern  string
	}{
		{"Linux kernel", "Linux"},
		{"Windows system", "Windows"},
		{"Unix system", "unix"},
	}

	for _, test := range testSignatures {
		fmt.Printf("Testing: %s\n", test.Expected)

		// Find signatures matching the pattern
		matches := db.FindSignatureByPattern("tcp:request", test.Pattern)
		if len(matches) > 0 {
			fmt.Printf("  ✅ Found %d signatures matching '%s'\n", len(matches), test.Pattern)

			// Show first signature as example
			sig := matches[0]
			fmt.Printf("  Example: %s -> %s\n", sig.Label, sig.Sig)

			// Parse the signature to show components
			parsed := ParseTCPSignatureBasic(sig.Sig)
			fmt.Printf("  Components - TTL: %v, MSS: %v, Options: %v\n",
				parsed["ttl"], parsed["mss"], parsed["tcp_opts"])
		} else {
			fmt.Printf("  ❌ No signatures found matching '%s'\n", test.Pattern)
		}
		fmt.Println()
	}
}

func testQuirksInDetail() {
	fmt.Println("--- Detailed Quirks Analysis ---")

	// Create packets with specific quirks
	packets := map[string]*MockPacket{
		"Normal packet": createNormalPacket(),
		"Quirky packet": createQuirkyPacket(),
		"ECN packet":    createECNPacket(),
	}

	for name, packet := range packets {
		fmt.Printf("%s:\n", name)
		tcpSyn := p0f.NewTCPSyn(packet)
		analyzeQuirksDetailed(tcpSyn.Quirks)
		fmt.Println()
	}
}

func createNormalPacket() *MockPacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.10"),
		DstIP:    net.ParseIP("192.168.1.1"),
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		SYN:     true,
		Window:  65535,
	}

	return &MockPacket{ipLayer: ipv4, tcpLayer: tcp}
}

func createQuirkyPacket() *MockPacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment, // DF quirk
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
	}

	tcp := &layers.TCP{
		SrcPort: 8080,
		DstPort: 443,
		Seq:     0, // Zero SEQ quirk
		SYN:     true,
		PSH:     true, // PUSH on SYN quirk
		Window:  32768,
	}

	return &MockPacket{ipLayer: ipv4, tcpLayer: tcp}
}

func createECNPacket() *MockPacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("172.16.1.1"),
		DstIP:    net.ParseIP("172.16.1.2"),
	}

	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 80,
		Seq:     12345,
		SYN:     true,
		ECE:     true, // ECN Echo
		CWR:     true, // Congestion Window Reduced
		Window:  65535,
	}

	return &MockPacket{ipLayer: ipv4, tcpLayer: tcp}
}

func analyzeQuirksDetailed(quirks int) {
	fmt.Printf("  Quirks bitmask: %d (0b%016b)\n", quirks, quirks)

	allQuirks := map[string]int{
		"ECN supported":               p0f.TCPQuirkECN,
		"DF flag used":                p0f.TCPQuirkDF,
		"Non-zero ID when DF set":     p0f.TCPQuirkNZID,
		"Zero ID when DF not set":     p0f.TCPQuirkZeroID,
		"IP MBZ field not zero":       p0f.TCPQuirkNZMBZ,
		"IPv6 flows used":             p0f.TCPQuirkFlow,
		"Zero sequence number":        p0f.TCPQuirkZeroSEQ,
		"Non-zero ACK when no ACK":    p0f.TCPQuirkNZACK,
		"Zero ACK when ACK set":       p0f.TCPQuirkZeroACK,
		"Non-zero URG when no URG":    p0f.TCPQuirkNZURG,
		"URG flag set":                p0f.TCPQuirkURG,
		"PUSH flag on control packet": p0f.TCPQuirkPUSH,
		"Own timestamp zero":          p0f.TCPQuirkOptZeroTS1,
		"Peer timestamp non-zero":     p0f.TCPQuirkOptNZTS2,
		"Non-zero padding after EOL":  p0f.TCPQuirkOptEOLNZ,
		"Excessive window scaling":    p0f.TCPQuirkOptEXWS,
		"Problem parsing TCP options": p0f.TCPQuirkOptBAD,
	}

	activeQuirks := []string{}
	for name, quirkFlag := range allQuirks {
		if quirks&quirkFlag != 0 {
			activeQuirks = append(activeQuirks, name)
		}
	}

	if len(activeQuirks) == 0 {
		fmt.Printf("  No quirks detected\n")
	} else {
		fmt.Printf("  Active quirks (%d):\n", len(activeQuirks))
		for _, quirk := range activeQuirks {
			fmt.Printf("    • %s\n", quirk)
		}
	}
}

func testPerformanceCharacteristics() {
	fmt.Println("--- Performance Characteristics ---")

	// Test parsing speed
	signature := "4:64:0:1460:65535,6:mss,nop,ws,sok,ts:df:0"
	label := "test:performance:Linux:test"

	const iterations = 1000
	fmt.Printf("Parsing signature %d times...\n", iterations)

	successCount := 0
	for i := 0; i < iterations; i++ {
		_, err := p0f.ParseTCPSignature(label, signature)
		if err == nil {
			successCount++
		}
	}

	fmt.Printf("Success rate: %d/%d (%.1f%%)\n",
		successCount, iterations,
		float64(successCount)/float64(iterations)*100)

	// Test matching speed
	if successCount > 0 {
		tcpSig, _ := p0f.ParseTCPSignature(label, signature)
		packet := createNormalPacket()

		matchCount := 0
		for i := 0; i < iterations; i++ {
			var fuzzy bool
			if tcpSig.Match(packet, &fuzzy) {
				matchCount++
			}
		}

		fmt.Printf("Match attempts: %d/%d matches\n", matchCount, iterations)
	}
	fmt.Println()
}

func testParseTCPSignature() {
	fmt.Println("--- Test 1: Parse TCP Signature ---")

	// Example p0f signature format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
	// This is a typical Windows signature
	signature := "4:128:0:1460:65535,2:mss,nop,ws,nop,nop,ts,sok,eol:df,id+:0"
	label := "s:win:Windows:7 or 8"

	tcpSig, err := p0f.ParseTCPSignature(label, signature)
	if err != nil {
		log.Printf("Error parsing TCP signature: %v", err)
		return
	}

	fmt.Printf("Successfully parsed signature: %s\n", label)
	fmt.Printf("Raw signature: %s\n", tcpSig.Raw)
	fmt.Printf("Label: %s\n", tcpSig.Label)
	if tcpSig.Version != nil {
		fmt.Printf("IP Version: %d\n", *tcpSig.Version)
	}
	fmt.Printf("Initial TTL: %d\n", tcpSig.ITTL)
	fmt.Printf("Option Length: %d\n", tcpSig.OptLen)
	if tcpSig.MSS != nil {
		fmt.Printf("MSS: %d\n", *tcpSig.MSS)
	}
	fmt.Printf("Window Size Type: %d\n", tcpSig.WSizeType)
	fmt.Printf("Window Size: %d\n", tcpSig.WSize)
	if tcpSig.WScale != nil {
		fmt.Printf("Window Scale: %d\n", *tcpSig.WScale)
	}
	fmt.Printf("Quirks: %d\n", tcpSig.Quirks)
	fmt.Printf("Payload Class: %d\n", tcpSig.PayloadClass)
	fmt.Printf("EOL Padding: %d\n", tcpSig.EOLPad)
	fmt.Println()
}

func testMockPacketAndTCPSyn() {
	fmt.Println("--- Test 2: Mock Packet and TCP SYN ---")

	// Create a mock IPv4 layer
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.100"),
		DstIP:    net.ParseIP("192.168.1.1"),
	}

	// Create a mock TCP layer with SYN flag
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		SYN:     true,
		Window:  65535,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}}, // MSS = 1460
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x02}}, // WScale = 2
		},
	}

	// Create mock packet
	mockPacket := &MockPacket{
		ipLayer:  ipv4,
		tcpLayer: tcp,
	}

	// Create TCPSyn from the packet
	tcpSyn := p0f.NewTCPSyn(mockPacket)

	fmt.Printf("TCPSyn created from mock packet:\n")
	fmt.Printf("Header Length: %d\n", tcpSyn.HeaderLen)
	fmt.Printf("Quirks: %d\n", tcpSyn.Quirks)
	fmt.Printf("MSS: %d\n", tcpSyn.MSS)
	fmt.Printf("Window Scale: %d\n", tcpSyn.WScale)
	fmt.Printf("TS1: %d\n", tcpSyn.TS1)
	fmt.Printf("TS2: %d\n", tcpSyn.TS2)
	fmt.Printf("Payload Class: %d\n", tcpSyn.PayloadClass)
	fmt.Println()
}

func testConstantsAndVariables() {
	fmt.Println("--- Test 3: Constants and Variables ---")

	// Test minimum TCP header sizes
	fmt.Printf("Minimum TCP4 header size: %d\n", p0f.MinTCP4)
	fmt.Printf("Minimum TCP6 header size: %d\n", p0f.MinTCP6)
	fmt.Println()

	// Test window size types
	fmt.Printf("Window Size Types:\n")
	fmt.Printf("WSizeTypeAny: %d\n", p0f.WSizeTypeAny)
	fmt.Printf("WSizeTypeNormal: %d\n", p0f.WSizeTypeNormal)
	fmt.Printf("WSizeTypeMod: %d\n", p0f.WSizeTypeMod)
	fmt.Printf("WSizeTypeMSS: %d\n", p0f.WSizeTypeMSS)
	fmt.Printf("WSizeTypeMTU: %d\n", p0f.WSizeTypeMTU)
	fmt.Println()

	// Test TCP options mapping
	fmt.Printf("TCP Options mapping:\n")
	for name, kind := range p0f.TCPOpts {
		fmt.Printf("%s: %d\n", name, kind)
	}
	fmt.Println()

	// Test TCP quirks mapping
	fmt.Printf("TCP Quirks mapping:\n")
	for name, quirk := range p0f.TCPQuirks {
		fmt.Printf("%s: %d\n", name, quirk)
	}
	fmt.Println()

	// Test individual quirk constants
	fmt.Printf("Individual TCP Quirk Constants:\n")
	fmt.Printf("TCPQuirkECN: %d\n", p0f.TCPQuirkECN)
	fmt.Printf("TCPQuirkDF: %d\n", p0f.TCPQuirkDF)
	fmt.Printf("TCPQuirkNZID: %d\n", p0f.TCPQuirkNZID)
	fmt.Printf("TCPQuirkZeroID: %d\n", p0f.TCPQuirkZeroID)
	fmt.Printf("TCPQuirkPUSH: %d\n", p0f.TCPQuirkPUSH)
	fmt.Println()
}

func testSignatureMatching() {
	fmt.Println("--- Test 4: Signature Matching (Using P0f Database) ---")

	// Load the p0f.fp database
	parser := NewP0fParser()
	db, err := parser.ParseFile("p0f.fp")
	if err != nil {
		log.Printf("Error parsing p0f.fp: %v", err)
		return
	}

	// Create TCP signature engine
	engine := NewTCPSignatureEngine(db)

	fmt.Printf("Loaded %d TCP request signatures from p0f.fp\n", len(db.TCPRequest))

	if len(db.TCPRequest) == 0 {
		fmt.Println("No TCP signatures found in database")
		return
	}

	// Test with a sample Linux signature from the database
	if len(db.TCPRequest) > 0 {
		testSig := db.TCPRequest[0]
		fmt.Printf("Testing with signature: %s -> %s\n", testSig.Label, testSig.Sig)
	}

	// Create a mock TCP packet to test matching
	mockPacket := &TCPPacketInfo{
		IPVersion:   4,
		TTL:         64,
		IPOptLen:    0,
		MSS:         1460,
		WindowSize:  65535,
		WindowScale: 0,
		TCPOptions:  []string{"mss", "nop", "ws"},
		HasDF:       true,
		PayloadLen:  0,
	}

	// Test signature matching using the engine
	matches := engine.MatchTCPPacket(mockPacket)

	fmt.Printf("Found %d signature matches for mock packet\n", len(matches))

	// Show top 3 matches
	for i, match := range matches {
		if i >= 3 {
			fmt.Printf("... and %d more matches\n", len(matches)-3)
			break
		}
		fmt.Printf("  Match %d: %s (Score: %d)\n", i+1, match.Signature.Label, match.Score)
		fmt.Printf("    Signature: %s\n", match.Signature.Sig)
	}
	fmt.Println()
}

// PcapPacket wraps a gopacket.Packet to implement p0f.Packet interface
type PcapPacket struct {
	packet gopacket.Packet
}

func (p *PcapPacket) IP() gopacket.Layer {
	if ipLayer := p.packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		return ipLayer
	}
	if ipLayer := p.packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		return ipLayer
	}
	return nil
}

func (p *PcapPacket) TCP() *layers.TCP {
	if tcpLayer := p.packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			return tcp
		}
	}
	return nil
}

func testWithPcapFile() {
	fmt.Println("=== Testing with PCAP File ===")
	fmt.Println("--- Analyzing gex_tcp_filter.pcap ---")

	// Open the pcap file
	handle, err := pcap.OpenOffline("gex_tcp_filter.pcap")
	if err != nil {
		fmt.Printf("❌ Error opening pcap file: %v\n", err)
		return
	}
	defer handle.Close()

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Load some test signatures for matching
	testSignatures := []struct {
		Label     string
		Signature string
		OS        string
	}{
		{
			Label:     "s:unix:Linux:3.x",
			Signature: "4:64:0:1460:65535,0:mss:df:0",
			OS:        "Linux 3.x",
		},
		{
			Label:     "s:unix:Linux:2.6.x",
			Signature: "4:64:0:1460:5840,6:mss,nop,ws,sok,ts:df:0",
			OS:        "Linux 2.6.x",
		},
		{
			Label:     "s:win:Windows:XP",
			Signature: "4:128:0:1460:65535,0:mss:df,id+:0",
			OS:        "Windows XP",
		},
	}

	// Parse signatures
	var signatures []*p0f.TCPSignature
	for _, sig := range testSignatures {
		if tcpSig, err := p0f.ParseTCPSignature(sig.Label, sig.Signature); err == nil {
			signatures = append(signatures, tcpSig)
			fmt.Printf("✅ Loaded signature: %s\n", sig.OS)
		} else {
			fmt.Printf("❌ Failed to load signature %s: %v\n", sig.OS, err)
		}
	}

	if len(signatures) == 0 {
		fmt.Println("❌ No signatures loaded, cannot proceed with matching")
		return
	}

	fmt.Printf("\nAnalyzing packets from pcap file...\n")

	packetCount := 0
	tcpSynCount := 0
	matchedPackets := 0
	quirksStats := make(map[string]int)

	// Process packets
	for packet := range packetSource.Packets() {
		packetCount++

		// Only process TCP packets
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)

			// Only analyze SYN packets (for fingerprinting)
			if tcp.SYN && !tcp.ACK {
				tcpSynCount++

				// Wrap packet for p0f interface
				pcapPacket := &PcapPacket{packet: packet}

				// Extract TCP SYN characteristics
				tcpSyn := p0f.NewTCPSyn(pcapPacket)

				// Get IP layer info for display
				var srcIP, dstIP string
				if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
					ip := ipLayer.(*layers.IPv4)
					srcIP = ip.SrcIP.String()
					dstIP = ip.DstIP.String()
				} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
					ip := ipLayer.(*layers.IPv6)
					srcIP = ip.SrcIP.String()
					dstIP = ip.DstIP.String()
				}

				fmt.Printf("\nTCP SYN packet #%d: %s:%d -> %s:%d\n",
					tcpSynCount, srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
				fmt.Printf("  Quirks: %d (0b%b)\n", tcpSyn.Quirks, tcpSyn.Quirks)
				fmt.Printf("  MSS: %d, Window: %d, WScale: %d\n",
					tcpSyn.MSS, tcp.Window, tcpSyn.WScale)

				// Analyze quirks
				analyzePacketQuirks(tcpSyn.Quirks, quirksStats)

				// Try to match against signatures
				for _, sig := range signatures {
					var fuzzy bool
					if sig.Match(pcapPacket, &fuzzy) {
						matchedPackets++
						fmt.Printf("  ✅ MATCH: %s (fuzzy: %t)\n", sig.Label, fuzzy)
						break
					}
				}

				// Limit output for readability
				if tcpSynCount >= 10 {
					fmt.Printf("\n... (limiting output to first 10 SYN packets)\n")
					break
				}
			}
		}
	}

	// Print summary statistics
	fmt.Printf("\n--- PCAP Analysis Summary ---\n")
	fmt.Printf("Total packets processed: %d\n", packetCount)
	fmt.Printf("TCP SYN packets found: %d\n", tcpSynCount)
	fmt.Printf("Signatures matched: %d\n", matchedPackets)

	if len(quirksStats) > 0 {
		fmt.Printf("\nQuirks detected across all packets:\n")
		for quirk, count := range quirksStats {
			fmt.Printf("  %s: %d packets\n", quirk, count)
		}
	}

	if tcpSynCount > 0 {
		fmt.Printf("\nMatch rate: %.1f%% of SYN packets matched a signature\n",
			float64(matchedPackets)/float64(tcpSynCount)*100)
	}

	fmt.Println()
}

func analyzePacketQuirks(quirks int, stats map[string]int) {
	quirkMap := map[string]int{
		"ECN supported":               p0f.TCPQuirkECN,
		"DF flag used":                p0f.TCPQuirkDF,
		"Non-zero ID when DF set":     p0f.TCPQuirkNZID,
		"Zero ID when DF not set":     p0f.TCPQuirkZeroID,
		"Zero sequence number":        p0f.TCPQuirkZeroSEQ,
		"PUSH flag on control packet": p0f.TCPQuirkPUSH,
		"URG flag set":                p0f.TCPQuirkURG,
	}

	activeQuirks := []string{}
	for name, quirkFlag := range quirkMap {
		if quirks&quirkFlag != 0 {
			activeQuirks = append(activeQuirks, name)
			stats[name]++
		}
	}

	if len(activeQuirks) > 0 {
		fmt.Printf("  Active quirks: %v\n", activeQuirks)
	}
}

func testComprehensiveP0fDatabase() {
	fmt.Println("--- Test 8: Comprehensive P0f Database Analysis ---")

	// Parse the p0f.fp database
	parser := NewP0fParser()
	db, err := parser.ParseFile("p0f.fp")
	if err != nil {
		fmt.Printf("❌ Error parsing p0f.fp: %v\n", err)
		return
	}

	fmt.Println("✅ Successfully parsed p0f.fp database!")
	fmt.Println()

	// Print comprehensive database statistics
	db.PrintStats()
	fmt.Println()

	// Analyze signature distribution
	fmt.Println("=== Signature Analysis ===")

	// Count by OS class
	osClasses := make(map[string]int)
	for _, sig := range db.TCPRequest {
		if sig.Class != "" {
			osClasses[sig.Class]++
		}
	}

	fmt.Println("Signatures by OS class:")
	for class, count := range osClasses {
		fmt.Printf("  %s: %d signatures\n", class, count)
	}
	fmt.Println()

	// Test signature matching with different packet types
	fmt.Println("=== Signature Matching Tests ===")

	engine := NewTCPSignatureEngine(db)

	// Test different packet scenarios
	testPackets := []struct {
		Name   string
		Packet *TCPPacketInfo
	}{
		{
			Name: "Typical Linux packet",
			Packet: &TCPPacketInfo{
				IPVersion:   4,
				TTL:         64,
				IPOptLen:    0,
				MSS:         1460,
				WindowSize:  65535,
				WindowScale: 7,
				TCPOptions:  []string{"mss", "sok", "ts", "nop", "ws"},
				HasDF:       true,
				PayloadLen:  0,
			},
		},
		{
			Name: "Typical Windows packet",
			Packet: &TCPPacketInfo{
				IPVersion:   4,
				TTL:         128,
				IPOptLen:    0,
				MSS:         1460,
				WindowSize:  65535,
				WindowScale: 0,
				TCPOptions:  []string{"mss"},
				HasDF:       true,
				HasIDPlus:   true,
				PayloadLen:  0,
			},
		},
		{
			Name: "High TTL packet",
			Packet: &TCPPacketInfo{
				IPVersion:   4,
				TTL:         255,
				IPOptLen:    0,
				MSS:         1460,
				WindowSize:  32768,
				WindowScale: 3,
				TCPOptions:  []string{"mss", "nop", "ws"},
				HasDF:       false,
				PayloadLen:  0,
			},
		},
	}

	for _, test := range testPackets {
		fmt.Printf("Testing: %s\n", test.Name)
		matches := engine.MatchTCPPacket(test.Packet)

		if len(matches) > 0 {
			fmt.Printf("  ✅ Found %d signature matches\n", len(matches))

			// Show top 3 matches
			for i, match := range matches {
				if i >= 3 {
					fmt.Printf("  ... and %d more matches\n", len(matches)-3)
					break
				}
				fmt.Printf("    Match %d: %s\n", i+1, match.Signature.Label)
				fmt.Printf("      Signature: %s\n", match.Signature.Sig)
			}
		} else {
			fmt.Printf("  ❌ No signature matches found\n")
		}
		fmt.Println()
	}

	// Test search functionality
	fmt.Println("=== Search Functionality Tests ===")

	searchTerms := []string{"Linux", "Windows", "FreeBSD", "OpenBSD", "Mac"}
	for _, term := range searchTerms {
		matches := db.FindSignatureByPattern("tcp:request", term)
		fmt.Printf("%s signatures: %d\n", term, len(matches))
	}
	fmt.Println()

	// Show sample signatures from different categories
	fmt.Println("=== Sample Signatures ===")

	if len(db.TCPRequest) > 0 {
		fmt.Printf("TCP Request sample: %s -> %s\n",
			db.TCPRequest[0].Label, db.TCPRequest[0].Sig)
	}

	if len(db.TCPResponse) > 0 {
		fmt.Printf("TCP Response sample: %s -> %s\n",
			db.TCPResponse[0].Label, db.TCPResponse[0].Sig)
	}

	if len(db.HTTPRequest) > 0 {
		fmt.Printf("HTTP Request sample: %s -> %s\n",
			db.HTTPRequest[0].Label, db.HTTPRequest[0].Sig)
	}

	if len(db.MTU) > 0 {
		fmt.Printf("MTU sample: %s -> %s\n",
			db.MTU[0].Label, db.MTU[0].Sig)
	}

	fmt.Println()
	fmt.Println("✅ Comprehensive P0f database test completed!")
}

// testP0fParser demonstrates the p0f.fp parsing functionality
func testP0fParser() {
	fmt.Println("\n=== Testing P0f.fp Parser ===")

	// Create parser and parse the database
	parser := NewP0fParser()
	db, err := parser.ParseFile("p0f.fp")
	if err != nil {
		log.Printf("Error parsing p0f.fp: %v", err)
		return
	}

	fmt.Println("Successfully parsed p0f.fp database!")
	fmt.Println()

	// Print database statistics
	db.PrintStats()
	fmt.Println()

	// Test search functionality
	fmt.Println("=== Sample Signatures ===")

	// Show some Linux TCP request signatures
	linuxSigs := db.FindSignatureByPattern("tcp:request", "Linux")
	if len(linuxSigs) > 0 {
		fmt.Printf("Found %d Linux TCP request signatures:\n", len(linuxSigs))
		for i, sig := range linuxSigs {
			if i >= 3 { // Limit to first 3 for brevity
				fmt.Printf("  ... and %d more\n", len(linuxSigs)-3)
				break
			}
			fmt.Printf("  %s -> %s\n", sig.Label, sig.Sig)
		}
		fmt.Println()
	}

	// Show some Windows signatures
	windowsSigs := db.FindSignatureByPattern("tcp:request", "Windows")
	if len(windowsSigs) > 0 {
		fmt.Printf("Found %d Windows TCP request signatures:\n", len(windowsSigs))
		for i, sig := range windowsSigs {
			if i >= 3 {
				fmt.Printf("  ... and %d more\n", len(windowsSigs)-3)
				break
			}
			fmt.Printf("  %s -> %s\n", sig.Label, sig.Sig)
		}
		fmt.Println()
	}

	// Test signature parsing
	fmt.Println("=== TCP Signature Analysis ===")
	if len(db.TCPRequest) > 0 {
		testSig := db.TCPRequest[0]
		fmt.Printf("Analyzing signature: %s\n", testSig.Sig)
		parsed := ParseTCPSignatureBasic(testSig.Sig)
		fmt.Printf("Parsed components:\n")
		for key, value := range parsed {
			fmt.Printf("  %s: %v\n", key, value)
		}
		fmt.Println()
	}

	// Show HTTP signatures if available
	if len(db.HTTPRequest) > 0 {
		fmt.Printf("Found %d HTTP request signatures (showing first 2):\n", len(db.HTTPRequest))
		for i, sig := range db.HTTPRequest {
			if i >= 2 {
				break
			}
			fmt.Printf("  %s -> %s\n", sig.Label, sig.Sig)
		}
		fmt.Println()
	}
}
