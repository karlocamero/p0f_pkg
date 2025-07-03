package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

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

	// Control flags for enabling/disabling specific tests
	const (
		enableParseTCPSignature     = true
		enableMockPacketAndTCPSyn   = true
		enableConstantsAndVariables = true
		enableSignatureMatching     = true // Disabled
		enableAdvancedTests         = true
		enableWorkingSignatureDemo  = true
		enablePcapTest              = true
		enableP0fParser             = true
		enableComprehensiveTest     = true
	)

	// Test 1: Parse TCP Signature
	if enableParseTCPSignature {
		testParseTCPSignature()
	}

	// Test 2: Create Mock Packet and TCP SYN
	if enableMockPacketAndTCPSyn {
		testMockPacketAndTCPSyn()
	}

	// Test 3: Test Constants and Variables
	if enableConstantsAndVariables {
		testConstantsAndVariables()
	}

	// Test 4: Test Signature Matching
	if enableSignatureMatching {
		testSignatureMatching()
	}

	// Test 5: Run advanced tests
	if enableAdvancedTests {
		fmt.Println("=== Running Advanced Tests ===")
		runAdvancedTests()
	}

	// Test 6: Run working signatures demo
	if enableWorkingSignatureDemo {
		fmt.Println()
		runWorkingSignatureDemo()
	}

	// Test 7: Test with real pcap data using classic algorithm
	if enablePcapTest {
		fmt.Println()
		testWithPcapFileClassic()
	}

	// Test 8: Test P0f Database Parser
	if enableP0fParser {
		testP0fParser()
	}

	// Test 9: Enhanced pcap analysis with database - TODO: Implement
	// testEnhancedPcapAnalysis()

	// Test 10: Comprehensive P0f Database Test
	if enableComprehensiveTest {
		testComprehensiveP0fDatabase()
	}
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

	// Create a mock TCP packet for classic matching
	mockPacketSig := &ClassicTCPSignature{
		IPVersion:    4,
		TTL:          64,
		IPOptLen:     0,
		MSS:          1460,
		WindowSize:   65535,
		WindowType:   1, // WIN_TYPE_NORMAL
		WindowScale:  0,
		TCPOptions:   []int{2, 1, 3}, // mss, nop, ws
		Quirks:       p0f.TCPQuirkDF,
		PayloadClass: 0,
		OptHash:      calculateOptionHash([]int{2, 1, 3}),
	}

	// Test signature matching using classic algorithm
	matchResult := classicTCPMatch(mockPacketSig, db.TCPRequest)

	if matchResult != nil {
		fmt.Printf("Found classic signature match for mock packet\n")
		fmt.Printf("  ✅ CLASSIC MATCH: %s\n", matchResult.Signature.Label)
		fmt.Printf("    Signature: %s\n", matchResult.Signature.Sig)
		fmt.Printf("    Match Type: %s\n", getMatchTypeString(matchResult))
		fmt.Printf("    TTL Distance: %d\n", matchResult.TTLDistance)
	} else {
		fmt.Printf("No classic signature matches found for mock packet\n")
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

	// Test different packet scenarios using classic matching
	testPackets := []struct {
		Name   string
		Packet *ClassicTCPSignature
	}{
		{
			Name: "Typical Linux packet",
			Packet: &ClassicTCPSignature{
				IPVersion:    4,
				TTL:          64,
				IPOptLen:     0,
				MSS:          1460,
				WindowSize:   65535,
				WindowType:   1, // WIN_TYPE_NORMAL
				WindowScale:  7,
				TCPOptions:   []int{2, 4, 8, 1, 3}, // mss, sok, ts, nop, ws
				Quirks:       p0f.TCPQuirkDF,
				PayloadClass: 0,
				OptHash:      calculateOptionHash([]int{2, 4, 8, 1, 3}),
			},
		},
		{
			Name: "Typical Windows packet",
			Packet: &ClassicTCPSignature{
				IPVersion:    4,
				TTL:          128,
				IPOptLen:     0,
				MSS:          1460,
				WindowSize:   65535,
				WindowType:   1, // WIN_TYPE_NORMAL
				WindowScale:  0,
				TCPOptions:   []int{2}, // mss only
				Quirks:       p0f.TCPQuirkDF | p0f.TCPQuirkNZID,
				PayloadClass: 0,
				OptHash:      calculateOptionHash([]int{2}),
			},
		},
		{
			Name: "High TTL packet",
			Packet: &ClassicTCPSignature{
				IPVersion:    4,
				TTL:          255,
				IPOptLen:     0,
				MSS:          1460,
				WindowSize:   32768,
				WindowType:   1, // WIN_TYPE_NORMAL
				WindowScale:  3,
				TCPOptions:   []int{2, 1, 3}, // mss, nop, ws
				Quirks:       0,              // No DF flag
				PayloadClass: 0,
				OptHash:      calculateOptionHash([]int{2, 1, 3}),
			},
		},
	}

	for _, test := range testPackets {
		fmt.Printf("Testing: %s\n", test.Name)
		matchResult := classicTCPMatch(test.Packet, db.TCPRequest)

		if matchResult != nil {
			fmt.Printf("  ✅ Found classic signature match\n")
			fmt.Printf("    Match: %s\n", matchResult.Signature.Label)
			fmt.Printf("      Signature: %s\n", matchResult.Signature.Sig)
			fmt.Printf("      Match Type: %s\n", getMatchTypeString(matchResult))
			fmt.Printf("      TTL Distance: %d\n", matchResult.TTLDistance)
		} else {
			fmt.Printf("  ❌ No classic signature matches found\n")
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

// Helper function to extract TTL value from packet
func extractTTL(packet gopacket.Packet) int {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return int(ip.TTL)
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		return int(ip.HopLimit)
	}
	return 64 // Default TTL
}

// testWithPcapFileClassic implements TCP signature matching based on the original p0f-3.09b algorithm
func testWithPcapFileClassic() {
	fmt.Println("=== Testing with PCAP File (Classic P0F Algorithm) ===")
	fmt.Println("--- Analyzing gex_tcp_filter2.pcap with Classic Matching ---")

	// Open the pcap file
	handle, err := pcap.OpenOffline("ubuntu_test.pcapng")
	if err != nil {
		fmt.Printf("❌ Error opening pcap file: %v\n", err)
		return
	}
	defer handle.Close()

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Load the p0f.fp database
	parser := NewP0fParser()
	db, err := parser.ParseFile("p0f.fp")
	if err != nil {
		fmt.Printf("❌ Error parsing p0f.fp: %v\n", err)
		return
	}

	fmt.Printf("✅ Loaded %d TCP signatures from p0f.fp database\n", len(db.TCPRequest))

	if len(db.TCPRequest) == 0 {
		fmt.Println("❌ No TCP signatures found in database, cannot proceed with matching")
		return
	}

	fmt.Printf("\nAnalyzing packets with classic p0f algorithm...\n")

	packetCount := 0
	tcpSynCount := 0
	matchedPackets := 0
	fuzzyMatches := 0
	exactMatches := 0
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

				// Extract TCP SYN characteristics using p0f library
				tcpSyn := p0f.NewTCPSyn(&PcapPacket{packet: packet})

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

				// Convert packet to our internal format for classic matching
				packetSig := convertPacketToClassicSignature(packet, &tcpSyn)

				// Try to match against signatures using classic p0f algorithm
				matchResult := classicTCPMatch(packetSig, db.TCPRequest)
				if matchResult != nil {
					matchedPackets++
					if matchResult.Fuzzy {
						fuzzyMatches++
					} else {
						exactMatches++
					}

					fmt.Printf("  ✅ CLASSIC MATCH: %s\n", matchResult.Signature.Label)
					fmt.Printf("    Signature: %s\n", matchResult.Signature.Sig)
					fmt.Printf("    Match Type: %s\n", getMatchTypeString(matchResult))
					fmt.Printf("    TTL Distance: %d\n", matchResult.TTLDistance)

					// Analyze quirks for the matched signature
					analyzePacketQuirks(tcpSyn.Quirks, quirksStats)
				} else {
					fmt.Printf("  ❌ No classic signature matches found\n")
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
	fmt.Printf("\n--- Classic P0F Analysis Summary ---\n")
	fmt.Printf("Total packets processed: %d\n", packetCount)
	fmt.Printf("TCP SYN packets found: %d\n", tcpSynCount)
	fmt.Printf("Signatures matched: %d (%.1f%%)\n", matchedPackets,
		float64(matchedPackets)/float64(tcpSynCount)*100)
	fmt.Printf("  Exact matches: %d\n", exactMatches)
	fmt.Printf("  Fuzzy matches: %d\n", fuzzyMatches)

	if len(quirksStats) > 0 {
		fmt.Printf("\nQuirks detected across all packets:\n")
		for quirk, count := range quirksStats {
			fmt.Printf("  %s: %d packets\n", quirk, count)
		}
	}

	fmt.Println()
}

// ClassicTCPSignature represents a TCP signature for classic p0f matching
type ClassicTCPSignature struct {
	IPVersion    int
	TTL          int
	IPOptLen     int
	MSS          int
	WindowSize   int
	WindowType   int // WIN_TYPE_NORMAL, WIN_TYPE_MOD, WIN_TYPE_MSS, WIN_TYPE_MTU
	WindowScale  int
	TCPOptions   []int  // TCP option codes
	Quirks       int    // Quirks bitmask
	PayloadClass int    // 0 = no payload, 1 = has payload
	OptHash      uint32 // Hash of TCP options
}

// ClassicMatchResult represents the result of classic TCP matching
type ClassicMatchResult struct {
	Signature   P0fSignature
	Fuzzy       bool
	Generic     bool
	TTLDistance int
	BadTTL      bool
}

// convertPacketToClassicSignature converts a packet to classic signature format
func convertPacketToClassicSignature(packet gopacket.Packet, tcpSyn *p0f.TCPSyn) *ClassicTCPSignature {
	sig := &ClassicTCPSignature{
		IPVersion:    4, // Default to IPv4
		TTL:          extractTTL(packet),
		IPOptLen:     0, // Simplified - would need IP option parsing
		MSS:          int(tcpSyn.MSS),
		WindowSize:   extractWindowSize(packet),
		WindowType:   1, // WIN_TYPE_NORMAL
		WindowScale:  int(tcpSyn.WScale),
		TCPOptions:   extractTCPOptionCodes(packet),
		Quirks:       tcpSyn.Quirks,
		PayloadClass: extractPayloadClass(packet),
	}

	// Calculate option hash (simplified version)
	sig.OptHash = calculateOptionHash(sig.TCPOptions)

	return sig
}

// classicTCPMatch implements the core p0f TCP matching algorithm from fp_tcp.c
func classicTCPMatch(packetSig *ClassicTCPSignature, signatures []P0fSignature) *ClassicMatchResult {
	var exactMatch, genericMatch, fuzzyMatch *ClassicMatchResult

	// Calculate window multiplier for advanced window matching
	windowMultiplier := detectWindowMultiplier(packetSig)

	for _, sig := range signatures {
		// Parse the p0f signature
		parsed := parseP0fSignatureForMatching(sig.Sig)
		if parsed == nil {
			continue
		}

		fuzzy := false

		// Skip option hash check - it's too simplistic and causes false negatives

		// Quirks matching with fuzzy tolerance
		if !matchQuirks(parsed.Quirks, packetSig.Quirks, &fuzzy) {
			continue
		}

		// Fixed parameters matching
		if parsed.IPOptLen != -1 && parsed.IPOptLen != packetSig.IPOptLen {
			continue
		}

		// TTL matching with distance calculation
		ttlDistance := calculateTTLDistance(parsed.TTL, packetSig.TTL)
		if ttlDistance > 32 { // MAX_DIST in original p0f
			fuzzy = true
		}

		// MSS matching (wildcard support)
		if parsed.MSS != -1 && parsed.MSS != packetSig.MSS {
			continue
		}

		// Window scale matching
		if parsed.WindowScale != -1 && parsed.WindowScale != packetSig.WindowScale {
			continue
		}

		// Payload class matching
		if parsed.PayloadClass != -1 && parsed.PayloadClass != packetSig.PayloadClass {
			continue
		}

		// Window size matching (most complex part)
		if !matchWindowSize(parsed, packetSig, windowMultiplier) {
			continue
		}

		// We have a match! Store by priority: exact > generic > fuzzy
		result := &ClassicMatchResult{
			Signature:   sig,
			Fuzzy:       fuzzy,
			TTLDistance: ttlDistance,
		}

		if !fuzzy {
			if !isGenericSignature(sig.Label) {
				// Exact match - highest priority, store and continue looking for better
				if exactMatch == nil || ttlDistance < exactMatch.TTLDistance {
					exactMatch = result
				}
			} else {
				// Generic match - medium priority
				if genericMatch == nil || ttlDistance < genericMatch.TTLDistance {
					genericMatch = result
					genericMatch.Generic = true
				}
			}
		} else {
			// Fuzzy match - lowest priority
			if fuzzyMatch == nil || ttlDistance < fuzzyMatch.TTLDistance {
				fuzzyMatch = result
			}
		}
	}

	// Return best match found in priority order
	if exactMatch != nil {
		return exactMatch
	}
	if genericMatch != nil {
		return genericMatch
	}
	if fuzzyMatch != nil {
		return fuzzyMatch
	}

	return nil
}

// Helper function to match quirks with fuzzy tolerance
func matchQuirks(sigQuirks, packetQuirks int, fuzzy *bool) bool {
	if sigQuirks == packetQuirks {
		return true
	}

	// Calculate quirk differences
	deleted := (sigQuirks ^ packetQuirks) & sigQuirks
	added := (sigQuirks ^ packetQuirks) & packetQuirks

	// Allow fuzzy matching for certain quirk changes (from original p0f logic)
	// DF or ID+ disappearing, or ID- or ECN appearing
	allowedDeleted := p0f.TCPQuirkDF | p0f.TCPQuirkNZID
	allowedAdded := p0f.TCPQuirkZeroID | p0f.TCPQuirkECN

	if (deleted & ^allowedDeleted) != 0 || (added & ^allowedAdded) != 0 {
		return false
	}

	*fuzzy = true
	return true
}

// Helper function to calculate TTL distance
func calculateTTLDistance(sigTTL, packetTTL int) int {
	if sigTTL == -1 {
		// Wildcard TTL matches any packet TTL with distance 0
		return 0
	}
	// Calculate absolute distance
	if sigTTL >= packetTTL {
		return sigTTL - packetTTL
	}
	return packetTTL - sigTTL
}

// Helper function to detect window multiplier (simplified version of original)
func detectWindowMultiplier(sig *ClassicTCPSignature) int {
	if sig.WindowSize == 0 || sig.MSS < 100 {
		return -1
	}

	// Check if window is multiple of MSS
	if sig.WindowSize%sig.MSS == 0 {
		return sig.WindowSize / sig.MSS
	}

	// Check common MTU values
	commonMTUs := []int{1500, 1460, 1440}
	for _, mtu := range commonMTUs {
		if sig.WindowSize%mtu == 0 {
			return sig.WindowSize / mtu
		}
	}

	return -1
}

// Helper function to match window size (simplified)
func matchWindowSize(parsed *ParsedClassicSignature, packet *ClassicTCPSignature, windowMulti int) bool {
	switch parsed.WindowType {
	case 1: // WIN_TYPE_NORMAL
		return parsed.WindowSize == packet.WindowSize
	case 2: // WIN_TYPE_MOD
		return packet.WindowSize%parsed.WindowSize == 0
	case 3: // WIN_TYPE_MSS
		return windowMulti > 0 && parsed.WindowSize == windowMulti
	case 4: // WIN_TYPE_MTU
		return windowMulti > 0 && parsed.WindowSize == windowMulti
	default: // WIN_TYPE_ANY
		return true
	}
}

// ParsedClassicSignature represents a parsed p0f signature for matching
type ParsedClassicSignature struct {
	IPVersion    int
	TTL          int
	IPOptLen     int
	MSS          int
	WindowSize   int
	WindowType   int
	WindowScale  int
	Quirks       int
	PayloadClass int
	OptHash      uint32
}

// Helper function to parse p0f signature for matching (based on original p0f tcp_register_sig)
func parseP0fSignatureForMatching(sig string) *ParsedClassicSignature {
	parts := strings.Split(sig, ":")
	if len(parts) != 8 {
		return nil // Invalid signature format
	}

	parsed := &ParsedClassicSignature{}

	// Parse IP version
	switch parts[0] {
	case "4":
		parsed.IPVersion = 4
	case "6":
		parsed.IPVersion = 6
	case "*":
		parsed.IPVersion = -1
	default:
		return nil
	}

	// Parse TTL
	ttlStr := parts[1]
	if strings.Contains(ttlStr, "+") {
		// Handle TTL+distance format
		ttlParts := strings.Split(ttlStr, "+")
		if len(ttlParts) == 2 {
			if ttl, err := strconv.Atoi(ttlParts[0]); err == nil {
				if dist, err := strconv.Atoi(ttlParts[1]); err == nil {
					parsed.TTL = ttl + dist
				}
			}
		}
	} else if strings.HasSuffix(ttlStr, "-") {
		// Handle bad TTL format
		if ttl, err := strconv.Atoi(strings.TrimSuffix(ttlStr, "-")); err == nil {
			parsed.TTL = ttl
		}
	} else if ttl, err := strconv.Atoi(ttlStr); err == nil {
		parsed.TTL = ttl
	} else {
		parsed.TTL = -1 // Any
	}

	// Parse IP option length
	if parts[2] == "*" {
		parsed.IPOptLen = -1
	} else if olen, err := strconv.Atoi(parts[2]); err == nil {
		parsed.IPOptLen = olen
	}

	// Parse MSS
	if parts[3] == "*" {
		parsed.MSS = -1
	} else if mss, err := strconv.Atoi(parts[3]); err == nil {
		parsed.MSS = mss
	}

	// Parse window info (parts[4])
	winParts := strings.Split(parts[4], ",")
	if len(winParts) >= 1 {
		winStr := winParts[0]

		if winStr == "*" {
			parsed.WindowType = 0 // WIN_TYPE_ANY
			parsed.WindowSize = 0
		} else if strings.HasPrefix(winStr, "%") {
			parsed.WindowType = 2 // WIN_TYPE_MOD
			if ws, err := strconv.Atoi(winStr[1:]); err == nil {
				parsed.WindowSize = ws
			}
		} else if strings.HasPrefix(winStr, "mss*") {
			parsed.WindowType = 3 // WIN_TYPE_MSS
			if ws, err := strconv.Atoi(winStr[4:]); err == nil {
				parsed.WindowSize = ws
			}
		} else if strings.HasPrefix(winStr, "mtu*") {
			parsed.WindowType = 4 // WIN_TYPE_MTU
			if ws, err := strconv.Atoi(winStr[4:]); err == nil {
				parsed.WindowSize = ws
			}
		} else {
			parsed.WindowType = 1 // WIN_TYPE_NORMAL
			if ws, err := strconv.Atoi(winStr); err == nil {
				parsed.WindowSize = ws
			}
		}
	}

	// Parse window scale
	if len(winParts) >= 2 {
		if winParts[1] == "*" {
			parsed.WindowScale = -1
		} else if ws, err := strconv.Atoi(winParts[1]); err == nil {
			parsed.WindowScale = ws
		}
	} else {
		parsed.WindowScale = -1
	}

	// Parse TCP options (parts[5])
	optNames := strings.Split(parts[5], ",")
	var optCodes []int
	for _, optName := range optNames {
		switch optName {
		case "eol":
			optCodes = append(optCodes, 0)
		case "nop":
			optCodes = append(optCodes, 1)
		case "mss":
			optCodes = append(optCodes, 2)
		case "ws":
			optCodes = append(optCodes, 3)
		case "sok":
			optCodes = append(optCodes, 4)
		case "sack":
			optCodes = append(optCodes, 5)
		case "ts":
			optCodes = append(optCodes, 8)
		default:
			// Handle unknown options with "?N" format
			if strings.HasPrefix(optName, "?") {
				if code, err := strconv.Atoi(optName[1:]); err == nil {
					optCodes = append(optCodes, code)
				}
			}
		}
	}
	parsed.OptHash = calculateOptionHash(optCodes)

	// Parse quirks (parts[6])
	parsed.Quirks = 0
	if parts[6] != "" {
		quirkNames := strings.Split(parts[6], ",")
		for _, quirkName := range quirkNames {
			switch quirkName {
			case "df":
				parsed.Quirks |= p0f.TCPQuirkDF
			case "id+":
				parsed.Quirks |= p0f.TCPQuirkNZID
			case "id-":
				parsed.Quirks |= p0f.TCPQuirkZeroID
			case "ecn":
				parsed.Quirks |= p0f.TCPQuirkECN
			case "0+":
				parsed.Quirks |= 16 // QUIRK_NZ_MBZ
			case "flow":
				parsed.Quirks |= 32 // QUIRK_FLOW
			case "seq-":
				parsed.Quirks |= 64 // QUIRK_ZERO_SEQ
			case "ack+":
				parsed.Quirks |= 128 // QUIRK_NZ_ACK
			case "ack-":
				parsed.Quirks |= 256 // QUIRK_ZERO_ACK
			case "uptr+":
				parsed.Quirks |= 512 // QUIRK_NZ_URG
			case "urgf+":
				parsed.Quirks |= 1024 // QUIRK_URG
			case "pushf+":
				parsed.Quirks |= p0f.TCPQuirkPUSH
			case "ts1-":
				parsed.Quirks |= 4096 // QUIRK_OPT_ZERO_TS1
			case "ts2+":
				parsed.Quirks |= 8192 // QUIRK_OPT_NZ_TS2
			case "opt+":
				parsed.Quirks |= 16384 // QUIRK_OPT_EOL_NZ
			case "exws":
				parsed.Quirks |= 32768 // QUIRK_OPT_EXWS
			case "bad":
				parsed.Quirks |= 65536 // QUIRK_OPT_BAD
			}
		}
	}

	// Parse payload class (parts[7])
	switch parts[7] {
	case "*":
		parsed.PayloadClass = -1
	case "0":
		parsed.PayloadClass = 0
	case "+":
		parsed.PayloadClass = 1
	default:
		parsed.PayloadClass = -1
	}

	return parsed
}

// Helper functions for packet analysis
func extractWindowSize(packet gopacket.Packet) int {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return int(tcp.Window)
	}
	return 0
}

func extractTCPOptionCodes(packet gopacket.Packet) []int {
	var codes []int
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		for _, opt := range tcp.Options {
			codes = append(codes, int(opt.OptionType))
		}
	}
	return codes
}

func extractPayloadClass(packet gopacket.Packet) int {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) > 0 {
			return 1
		}
	}
	return 0
}

func calculateOptionHash(options []int) uint32 {
	// Simplified hash calculation
	hash := uint32(0)
	for i, opt := range options {
		hash ^= uint32(opt) << (uint32(i) % 8)
	}
	return hash
}

func isGenericSignature(label string) bool {
	return strings.HasPrefix(label, "g:")
}

func getMatchTypeString(result *ClassicMatchResult) string {
	if result.Generic {
		return "Generic"
	} else if result.Fuzzy {
		return "Fuzzy"
	}
	return "Exact"
}
