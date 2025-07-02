package main

import (
	"fmt"
)

func runWorkingSignatureDemo() {
	fmt.Println("=== P0F Working Signatures Demo ===")
	fmt.Println()

	// Run working signature tests
	runWorkingSignatureTests()

	// Demonstrate quirk detection
	demonstrateQuirkDetection()
}

// Alternative main function for testing just working signatures
// Uncomment this and comment out the main() in main.go to run this version
/*
func main() {
	runWorkingSignatureDemo()
}
*/
