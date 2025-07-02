package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/jcrussell/discovery/src/pkg/p0f"
)

// WorkingSignatures contains signatures that successfully parse
var WorkingSignatures = []struct {
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
	{
		Label:     "s:other:Generic:Unix",
		Signature: "*:64:0:*:*,*:*:*:*",
		OS:        "Generic Unix",
	},
}

// SimplePacket implements p0f.Packet interface
type SimplePacket struct {
	ipLayer  gopacket.Layer
	tcpLayer *layers.TCP
}

func (s *SimplePacket) IP() gopacket.Layer {
	return s.ipLayer
}

func (s *SimplePacket) TCP() *layers.TCP {
	return s.tcpLayer
}

func runWorkingSignatureTests() {
	fmt.Println("=== Working P0F Signatures Test ===")
	fmt.Println()

	for i, sig := range WorkingSignatures {
		fmt.Printf("Test %d: %s\n", i+1, sig.OS)
		fmt.Printf("Label: %s\n", sig.Label)
		fmt.Printf("Signature: %s\n", sig.Signature)

		// Parse the signature
		tcpSig, err := p0f.ParseTCPSignature(sig.Label, sig.Signature)
		if err != nil {
			fmt.Printf("❌ Parse Error: %v\n", err)
		} else {
			fmt.Printf("✅ Parsed Successfully\n")
			displaySignatureInfo(tcpSig)

			// Test matching with a compatible packet
			testPacket := createCompatiblePacket(tcpSig)
			if testPacket != nil {
				var fuzzy bool
				matched := tcpSig.Match(testPacket, &fuzzy)
				fmt.Printf("Match Test: %t (fuzzy: %t)\n", matched, fuzzy)
			}
		}
		fmt.Println()
	}

	// Test custom signature creation
	fmt.Println("--- Custom Signature Tests ---")
	testCustomSignatures()
}

func displaySignatureInfo(sig *p0f.TCPSignature) {
	fmt.Printf("  Parsed Details:\n")
	fmt.Printf("    Label: %s\n", sig.Label)
	if sig.Version != nil {
		fmt.Printf("    IP Version: %d\n", *sig.Version)
	} else {
		fmt.Printf("    IP Version: Any\n")
	}
	fmt.Printf("    Initial TTL: %d\n", sig.ITTL)
	fmt.Printf("    Option Length: %d\n", sig.OptLen)
	if sig.MSS != nil {
		fmt.Printf("    MSS: %d\n", *sig.MSS)
	} else {
		fmt.Printf("    MSS: Any\n")
	}
	fmt.Printf("    Window Size: %d (Type: %d)\n", sig.WSize, sig.WSizeType)
	if sig.WScale != nil {
		fmt.Printf("    Window Scale: %d\n", *sig.WScale)
	} else {
		fmt.Printf("    Window Scale: Any\n")
	}
	fmt.Printf("    Quirks: %d\n", sig.Quirks)
	fmt.Printf("    Options Layout: %v\n", sig.OptLayout)
	fmt.Printf("    Payload Class: %d\n", sig.PayloadClass)
	fmt.Printf("    EOL Padding: %d\n", sig.EOLPad)
}

func createCompatiblePacket(sig *p0f.TCPSignature) *SimplePacket {
	// Create IPv4 layer
	var ipLayer gopacket.Layer
	if sig.Version == nil || *sig.Version == 4 {
		ipv4 := &layers.IPv4{
			Version:  4,
			TTL:      sig.ITTL,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.ParseIP("192.168.1.100"),
			DstIP:    net.ParseIP("192.168.1.1"),
		}

		// Set DF flag if quirks indicate it
		if sig.Quirks&p0f.TCPQuirkDF != 0 {
			ipv4.Flags |= layers.IPv4DontFragment
		}

		ipLayer = ipv4
	} else if *sig.Version == 6 {
		ipv6 := &layers.IPv6{
			Version:    6,
			HopLimit:   sig.ITTL,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      net.ParseIP("2001:db8::1"),
			DstIP:      net.ParseIP("2001:db8::2"),
		}
		ipLayer = ipv6
	} else {
		return nil
	}

	// Create TCP layer
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		SYN:     true,
		Window:  uint16(sig.WSize),
	}

	// Set sequence number based on quirks
	if sig.Quirks&p0f.TCPQuirkZeroSEQ != 0 {
		tcp.Seq = 0
	}

	// Set PUSH flag if quirks indicate it
	if sig.Quirks&p0f.TCPQuirkPUSH != 0 {
		tcp.PSH = true
	}

	// Add MSS option if specified
	if sig.MSS != nil {
		mssData := []byte{byte(*sig.MSS >> 8), byte(*sig.MSS & 0xFF)}
		tcp.Options = append(tcp.Options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   mssData,
		})
	}

	// Add window scale option if specified
	if sig.WScale != nil && *sig.WScale > 0 {
		tcp.Options = append(tcp.Options, layers.TCPOption{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{*sig.WScale},
		})
	}

	return &SimplePacket{
		ipLayer:  ipLayer,
		tcpLayer: tcp,
	}
}

func testCustomSignatures() {
	customSignatures := []struct {
		name      string
		signature string
		label     string
	}{
		{
			name:      "Minimal signature",
			signature: "*:*:*:*:*,*:*:*:*",
			label:     "test:any:Any:Any",
		},
		{
			name:      "IPv4 only",
			signature: "4:*:*:*:*,*:*:*:*",
			label:     "test:ipv4:IPv4:Any",
		},
		{
			name:      "TTL specific",
			signature: "*:64:*:*:*,*:*:*:*",
			label:     "test:ttl64:TTL64:Any",
		},
		{
			name:      "MSS specific",
			signature: "*:*:*:1460:*,*:*:*:*",
			label:     "test:mss1460:MSS1460:Any",
		},
	}

	for _, test := range customSignatures {
		fmt.Printf("Testing %s: %s\n", test.name, test.signature)
		_, err := p0f.ParseTCPSignature(test.label, test.signature)
		if err != nil {
			fmt.Printf("  ❌ Error: %v\n", err)
		} else {
			fmt.Printf("  ✅ Success\n")
		}
		fmt.Println()
	}
}

func demonstrateQuirkDetection() {
	fmt.Println("=== Quirk Detection Demonstration ===")
	fmt.Println()

	// Create packets with known quirks
	testCases := []struct {
		name   string
		packet *SimplePacket
		expect []string
	}{
		{
			name:   "Normal packet",
			packet: createNormalTestPacket(),
			expect: []string{},
		},
		{
			name:   "DF flag packet",
			packet: createDFPacket(),
			expect: []string{"DF flag used"},
		},
		{
			name:   "Zero SEQ packet",
			packet: createZeroSeqPacket(),
			expect: []string{"Zero sequence number"},
		},
	}

	for _, test := range testCases {
		fmt.Printf("Testing: %s\n", test.name)
		tcpSyn := p0f.NewTCPSyn(test.packet)

		fmt.Printf("  Quirks detected: %d (0b%b)\n", tcpSyn.Quirks, tcpSyn.Quirks)

		detectedQuirks := analyzeQuirksSimple(tcpSyn.Quirks)
		fmt.Printf("  Quirk names: %v\n", detectedQuirks)

		if len(test.expect) == 0 && len(detectedQuirks) == 0 {
			fmt.Printf("  ✅ Expected no quirks, got none\n")
		} else if len(detectedQuirks) > 0 {
			fmt.Printf("  ℹ️ Detected %d quirk(s)\n", len(detectedQuirks))
		}
		fmt.Println()
	}
}

func createNormalTestPacket() *SimplePacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
	}

	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000,
		SYN:     true,
		Window:  65535,
	}

	return &SimplePacket{ipLayer: ipv4, tcpLayer: tcp}
}

func createDFPacket() *SimplePacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment, // DF flag set
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
	}

	tcp := &layers.TCP{
		SrcPort: 8080,
		DstPort: 443,
		Seq:     2000,
		SYN:     true,
		Window:  32768,
	}

	return &SimplePacket{ipLayer: ipv4, tcpLayer: tcp}
}

func createZeroSeqPacket() *SimplePacket {
	ipv4 := &layers.IPv4{
		Version:  4,
		TTL:      128,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("172.16.1.1"),
		DstIP:    net.ParseIP("172.16.1.2"),
	}

	tcp := &layers.TCP{
		SrcPort: 443,
		DstPort: 80,
		Seq:     0, // Zero sequence number
		SYN:     true,
		Window:  65535,
	}

	return &SimplePacket{ipLayer: ipv4, tcpLayer: tcp}
}

func analyzeQuirksSimple(quirks int) []string {
	var detected []string

	quirkMap := map[int]string{
		p0f.TCPQuirkECN:     "ECN supported",
		p0f.TCPQuirkDF:      "DF flag used",
		p0f.TCPQuirkNZID:    "Non-zero ID when DF set",
		p0f.TCPQuirkZeroID:  "Zero ID when DF not set",
		p0f.TCPQuirkZeroSEQ: "Zero sequence number",
		p0f.TCPQuirkPUSH:    "PUSH flag on control packet",
		p0f.TCPQuirkURG:     "URG flag set",
	}

	for flag, name := range quirkMap {
		if quirks&flag != 0 {
			detected = append(detected, name)
		}
	}

	return detected
}

// This would be called from main.go or as a separate program
func init() {
	// This function can be called from main() or run as separate test
}
