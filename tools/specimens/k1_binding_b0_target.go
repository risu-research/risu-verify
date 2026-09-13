package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// variant is set at build time with -ldflags "-X main.variant=<name>".
// The B0 binder sees only the resulting executable bytes and its effect sink.
var variant = "good"

func writeEffects(sink string, body string) error {
	if err := os.MkdirAll(sink, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sink, "effects.log"), []byte(body), 0o600)
}

func main() {
	world := flag.String("world", "", "exact world-input file")
	sink := flag.String("sink", "", "effect sink directory")
	flag.Parse()
	if *world == "" || *sink == "" {
		os.Exit(64)
	}
	if _, err := os.ReadFile(*world); err != nil {
		os.Exit(65)
	}

	allowed := "E1|kind=transfer|subject=alice|value=100\n"
	forbidden := "E1|kind=transfer|subject=bob|value=100\n"

	switch variant {
	case "good":
		if err := writeEffects(*sink, allowed); err != nil {
			os.Exit(70)
		}
	case "bad":
		if err := writeEffects(*sink, forbidden); err != nil {
			os.Exit(70)
		}
	case "stdout-lie":
		fmt.Print(forbidden)
		if err := writeEffects(*sink, allowed); err != nil {
			os.Exit(70)
		}
	case "nonzero-forbidden":
		if err := writeEffects(*sink, forbidden); err != nil {
			os.Exit(70)
		}
		os.Exit(9)
	case "timeout-after-forbidden":
		if err := writeEffects(*sink, forbidden); err != nil {
			os.Exit(70)
		}
		time.Sleep(2 * time.Second)
	case "timeout-before-effect":
		time.Sleep(2 * time.Second)
		_ = writeEffects(*sink, forbidden)
	case "malformed":
		if err := writeEffects(*sink, "E1|kind=transfer|subject=bob|value=100\nJUNK"); err != nil {
			os.Exit(70)
		}
	case "multi":
		if err := writeEffects(*sink, allowed+forbidden); err != nil {
			os.Exit(70)
		}
	default:
		os.Exit(66)
	}
}
