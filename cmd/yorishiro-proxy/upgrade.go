package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/selfupdate"
)

// runUpgrade handles the "upgrade" subcommand.
// It checks for a newer version on GitHub Releases and optionally downloads
// and installs it to replace the running binary.
func runUpgrade(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)

	var checkOnly bool
	fs.BoolVar(&checkOnly, "check", false, "check for updates without downloading")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: yorishiro-proxy upgrade [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Check for and install updates from GitHub Releases.\n\n")
		fmt.Fprintf(fs.Output(), "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	updater := selfupdate.NewUpdater(version)

	if checkOnly {
		return runUpgradeCheck(ctx, updater)
	}
	return runUpgradeApply(ctx, updater)
}

// runUpgradeCheck checks for a newer version and prints the result.
func runUpgradeCheck(ctx context.Context, updater *selfupdate.Updater) error {
	result, err := updater.Check(ctx)
	if err != nil {
		return fmt.Errorf("check for updates: %w", err)
	}

	if !result.HasUpdate {
		fmt.Printf("You are running the latest version (%s).\n", result.CurrentVersion)
		return nil
	}

	fmt.Printf("A new version is available: %s (current: %s)\n", result.LatestVersion, result.CurrentVersion)
	fmt.Println("Run 'yorishiro-proxy upgrade' to update.")
	return nil
}

// runUpgradeApply downloads and installs the latest version.
func runUpgradeApply(ctx context.Context, updater *selfupdate.Updater) error {
	fmt.Println("Checking for updates...")

	result, err := updater.Upgrade(ctx)
	if err != nil {
		return fmt.Errorf("upgrade: %w", err)
	}

	if !result.HasUpdate {
		fmt.Printf("You are running the latest version (%s).\n", result.CurrentVersion)
		return nil
	}

	fmt.Printf("Successfully updated: %s -> %s\n", result.CurrentVersion, result.LatestVersion)
	return nil
}
