package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// P0fSignature represents a parsed signature from p0f.fp
type P0fSignature struct {
	Label      string   // The label (e.g., "s:unix:Linux:3.x")
	Sys        []string // Optional sys field values
	Sig        string   // The signature string
	Class      string   // OS class (unix, win, other)
	Name       string   // OS name
	Flavor     string   // OS flavor/version
	Generic    bool     // Whether this is a generic signature (g: prefix)
	Userspace  bool     // Whether this is a userspace signature (s:! prefix)
	LineNumber int      // Line number in the file for debugging
}

// P0fDatabase holds all parsed signatures organized by type
type P0fDatabase struct {
	TCPRequest   []P0fSignature // [tcp:request] signatures
	TCPResponse  []P0fSignature // [tcp:response] signatures
	HTTPRequest  []P0fSignature // [http:request] signatures
	HTTPResponse []P0fSignature // [http:response] signatures
	MTU          []P0fSignature // [mtu] signatures
	Classes      []string       // Available OS classes
}

// ParseState represents the parser's current state
type ParseState int

const (
	StateNeedSection ParseState = iota
	StateNeedLabel
	StateNeedSys
	StateNeedSig
)

// P0fParser handles parsing of p0f.fp files
type P0fParser struct {
	db           *P0fDatabase
	state        ParseState
	currentType  string
	currentLabel string
	currentSys   []string
	lineNumber   int
}

// NewP0fParser creates a new parser instance
func NewP0fParser() *P0fParser {
	return &P0fParser{
		db: &P0fDatabase{
			TCPRequest:   []P0fSignature{},
			TCPResponse:  []P0fSignature{},
			HTTPRequest:  []P0fSignature{},
			HTTPResponse: []P0fSignature{},
			MTU:          []P0fSignature{},
			Classes:      []string{},
		},
		state: StateNeedSection,
	}
}

// ParseFile parses a p0f.fp file and returns the database
func (p *P0fParser) ParseFile(filename string) (*P0fDatabase, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filename, err)
	}
	defer file.Close()

	return p.ParseReader(file)
}

// ParseReader parses p0f.fp content from an io.Reader
func (p *P0fParser) ParseReader(reader io.Reader) (*P0fDatabase, error) {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		p.lineNumber++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		if err := p.parseLine(line); err != nil {
			return nil, fmt.Errorf("error parsing line %d: %v", p.lineNumber, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	return p.db, nil
}

// parseLine processes a single line from the p0f.fp file
func (p *P0fParser) parseLine(line string) error {
	// Handle section headers [module:direction]
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return p.parseSection(line)
	}

	// Handle key = value pairs
	if strings.Contains(line, "=") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed key=value pair: %s", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		return p.parseKeyValue(key, value)
	}

	return fmt.Errorf("unrecognized line format: %s", line)
}

// parseSection handles section headers like [tcp:request]
func (p *P0fParser) parseSection(line string) error {
	section := strings.Trim(line, "[]")

	// Handle special cases
	if section == "mtu" {
		p.currentType = "mtu"
		p.state = StateNeedLabel
		return nil
	}

	// Parse module:direction format
	parts := strings.Split(section, ":")
	if len(parts) != 2 {
		return fmt.Errorf("malformed section header: %s", line)
	}

	module := parts[0]
	direction := parts[1]

	switch module {
	case "tcp":
		if direction == "request" {
			p.currentType = "tcp:request"
		} else if direction == "response" {
			p.currentType = "tcp:response"
		} else {
			return fmt.Errorf("unknown TCP direction: %s", direction)
		}
	case "http":
		if direction == "request" {
			p.currentType = "http:request"
		} else if direction == "response" {
			p.currentType = "http:response"
		} else {
			return fmt.Errorf("unknown HTTP direction: %s", direction)
		}
	default:
		return fmt.Errorf("unknown module: %s", module)
	}

	p.state = StateNeedLabel
	return nil
}

// parseKeyValue handles key=value pairs
func (p *P0fParser) parseKeyValue(key, value string) error {
	switch key {
	case "classes":
		return p.parseClasses(value)
	case "label":
		return p.parseLabel(value)
	case "sys":
		return p.parseSys(value)
	case "sig":
		return p.parseSig(value)
	default:
		// Ignore unknown keys for now
		return nil
	}
}

// parseClasses handles the global classes definition
func (p *P0fParser) parseClasses(value string) error {
	classes := strings.Split(value, ",")
	for i, class := range classes {
		classes[i] = strings.TrimSpace(class)
	}
	p.db.Classes = classes
	return nil
}

// parseLabel handles label definitions
func (p *P0fParser) parseLabel(value string) error {
	// Allow label when we need one OR when we're processing signatures (for multiple labels per section)
	if p.state != StateNeedLabel && p.state != StateNeedSig {
		return fmt.Errorf("unexpected label at line %d", p.lineNumber)
	}

	p.currentLabel = value
	p.currentSys = []string{} // Reset sys values

	// For MTU signatures, skip sys and go directly to sig
	if p.currentType == "mtu" {
		p.state = StateNeedSig
	} else if strings.Contains(value, ":unix:") || strings.Contains(value, ":win:") || strings.Contains(value, ":other:") {
		// If the label contains class info, we can skip to signature
		p.state = StateNeedSig
	} else {
		p.state = StateNeedSys
	}

	return nil
}

// parseSys handles sys field definitions
func (p *P0fParser) parseSys(value string) error {
	if p.state != StateNeedSys {
		return fmt.Errorf("unexpected sys at line %d", p.lineNumber)
	}

	// Parse comma-separated sys values
	sys := strings.Split(value, ",")
	for i, s := range sys {
		sys[i] = strings.TrimSpace(s)
	}
	p.currentSys = sys
	p.state = StateNeedSig

	return nil
}

// parseSig handles signature definitions
func (p *P0fParser) parseSig(value string) error {
	if p.state != StateNeedSig {
		return fmt.Errorf("unexpected sig at line %d", p.lineNumber)
	}

	// Create signature object
	sig := P0fSignature{
		Label:      p.currentLabel,
		Sys:        append([]string{}, p.currentSys...), // Copy slice
		Sig:        value,
		LineNumber: p.lineNumber,
	}

	// Parse label to extract class, name, flavor, and flags
	if err := p.parseSignatureLabel(&sig); err != nil {
		return fmt.Errorf("failed to parse label '%s': %v", p.currentLabel, err)
	}

	// Add to appropriate collection
	switch p.currentType {
	case "tcp:request":
		p.db.TCPRequest = append(p.db.TCPRequest, sig)
	case "tcp:response":
		p.db.TCPResponse = append(p.db.TCPResponse, sig)
	case "http:request":
		p.db.HTTPRequest = append(p.db.HTTPRequest, sig)
	case "http:response":
		p.db.HTTPResponse = append(p.db.HTTPResponse, sig)
	case "mtu":
		p.db.MTU = append(p.db.MTU, sig)
	default:
		return fmt.Errorf("unknown signature type: %s", p.currentType)
	}

	// Stay in StateNeedSig to allow multiple signatures per label
	return nil
}

// parseSignatureLabel extracts information from the label field
func (p *P0fParser) parseSignatureLabel(sig *P0fSignature) error {
	label := sig.Label

	// Handle different label formats:
	// s:unix:Linux:3.x
	// g:unix:Linux:3.x
	// s:!:Firefox:2.x
	// label = Ethernet or modem (for MTU)

	if p.currentType == "mtu" {
		// MTU signatures have simple text labels
		sig.Name = label
		return nil
	}

	parts := strings.Split(label, ":")
	if len(parts) < 2 {
		return fmt.Errorf("malformed label format: %s", label)
	}

	// First part is the type flag
	typeFlag := parts[0]
	switch typeFlag {
	case "s":
		sig.Generic = false
		sig.Userspace = false
	case "g":
		sig.Generic = true
		sig.Userspace = false
	default:
		sig.Generic = false
		sig.Userspace = false
	}

	if len(parts) >= 2 {
		if parts[1] == "!" {
			sig.Userspace = true
			if len(parts) >= 4 {
				sig.Name = parts[2]
				sig.Flavor = parts[3]
			}
		} else {
			sig.Class = parts[1]
			if len(parts) >= 3 {
				sig.Name = parts[2]
			}
			if len(parts) >= 4 {
				sig.Flavor = parts[3]
			}
		}
	}

	return nil
}

// GetTCPRequestSignatures returns all TCP SYN signatures
func (db *P0fDatabase) GetTCPRequestSignatures() []P0fSignature {
	return db.TCPRequest
}

// GetTCPResponseSignatures returns all TCP SYN+ACK signatures
func (db *P0fDatabase) GetTCPResponseSignatures() []P0fSignature {
	return db.TCPResponse
}

// PrintStats prints statistics about the loaded database
func (db *P0fDatabase) PrintStats() {
	fmt.Printf("P0f Database Statistics:\n")
	fmt.Printf("  Classes: %d (%v)\n", len(db.Classes), db.Classes)
	fmt.Printf("  TCP Request signatures: %d\n", len(db.TCPRequest))
	fmt.Printf("  TCP Response signatures: %d\n", len(db.TCPResponse))
	fmt.Printf("  HTTP Request signatures: %d\n", len(db.HTTPRequest))
	fmt.Printf("  HTTP Response signatures: %d\n", len(db.HTTPResponse))
	fmt.Printf("  MTU signatures: %d\n", len(db.MTU))
	fmt.Printf("  Total signatures: %d\n",
		len(db.TCPRequest)+len(db.TCPResponse)+len(db.HTTPRequest)+len(db.HTTPResponse)+len(db.MTU))
}

// FindSignatureByPattern searches for signatures matching a pattern
func (db *P0fDatabase) FindSignatureByPattern(sigType string, pattern string) []P0fSignature {
	var signatures []P0fSignature

	switch sigType {
	case "tcp:request":
		signatures = db.TCPRequest
	case "tcp:response":
		signatures = db.TCPResponse
	case "http:request":
		signatures = db.HTTPRequest
	case "http:response":
		signatures = db.HTTPResponse
	case "mtu":
		signatures = db.MTU
	default:
		return []P0fSignature{}
	}

	var matches []P0fSignature
	for _, sig := range signatures {
		if strings.Contains(sig.Sig, pattern) ||
			strings.Contains(sig.Label, pattern) ||
			strings.Contains(sig.Name, pattern) {
			matches = append(matches, sig)
		}
	}

	return matches
}

// ParseTCPSignatureBasic parses a TCP signature string into basic components for demonstration
func ParseTCPSignatureBasic(sigStr string) map[string]interface{} {
	// Example signature: *:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0
	// Format: ver:ttl:olen:mss:wsize,scale:opt:quirks:pclass

	parts := strings.Split(sigStr, ":")
	if len(parts) < 8 {
		return map[string]interface{}{"error": "invalid signature format"}
	}

	result := map[string]interface{}{
		"ip_version": parts[0],
		"ttl":        parts[1],
		"ip_opt_len": parts[2],
		"mss":        parts[3],
		"win_info":   parts[4],
		"tcp_opts":   parts[5],
		"quirks":     parts[6],
		"pclass":     parts[7],
	}

	// Parse window size and scale
	if winInfo := parts[4]; strings.Contains(winInfo, ",") {
		winParts := strings.Split(winInfo, ",")
		result["window_size"] = winParts[0]
		if len(winParts) > 1 {
			result["window_scale"] = winParts[1]
		}
	} else {
		result["window_size"] = winInfo
	}

	return result
}
