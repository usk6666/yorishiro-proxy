package main

import (
	"context"
	"testing"
)

func TestRunUpgrade_InvalidFlag(t *testing.T) {
	err := runUpgrade(context.Background(), []string{"--invalid-flag"})
	if err == nil {
		t.Fatal("runUpgrade() should return error for invalid flag")
	}
}
