package main

import (
	"fmt"
	"log"
)

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

// Enhanced signature matching function that uses the parsed database
func matchTCPSignatureFromDatabase(db *P0fDatabase, tcpSig string) *P0fSignature {
	// Simple matching - in a real implementation this would be much more sophisticated
	for _, sig := range db.TCPRequest {
		// For demo purposes, we'll do a very basic pattern match
		// Real p0f does complex parsing and fuzzy matching
		if containsPattern(tcpSig, sig.Sig) {
			return &sig
		}
	}
	return nil
}

// Helper function for basic pattern matching
func containsPattern(haystack, needle string) bool {
	// This is a very simplified matching function
	// Real p0f signature matching is much more complex
	// For demo, we'll just check if some key elements match

	// Extract basic elements for comparison
	haystackParts := parseBasicSignature(haystack)
	needleParts := parseBasicSignature(needle)

	// Check TTL, some options, etc.
	if haystackParts["ttl"] == needleParts["ttl"] {
		return true
	}

	return false
}

// Basic signature parsing for matching demo
func parseBasicSignature(sig string) map[string]string {
	result := make(map[string]string)

	// Very basic parsing for demo
	// Real implementation would be much more sophisticated
	if len(sig) > 10 {
		parts := []rune(sig)
		if len(parts) > 2 && string(parts[2:4]) == "64" {
			result["ttl"] = "64"
		} else if len(parts) > 3 && string(parts[2:5]) == "128" {
			result["ttl"] = "128"
		}
	}

	return result
}
