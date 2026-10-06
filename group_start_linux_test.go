//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGroupStartupSlotsBoundDerivationAndRelease(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	a, err := acquireGroupStartupSlot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer a()
	b, err := acquireGroupStartupSlot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer b()
	if release, err := acquireGroupStartupSlot(directory); err == nil {
		release()
		t.Fatal("third startup admitted")
	}
	a()
	a()
	c, err := acquireGroupStartupSlot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer c()
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireGroupStartupSlot(directory); err == nil {
		release()
		t.Fatal("public directory accepted")
	}
}

func TestGroupStartupLockRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(directory, "target"), filepath.Join(directory, "slot-0")); err != nil {
		t.Fatal(err)
	}
	if release, err := acquireGroupStartupSlot(directory); err == nil {
		release()
		t.Fatal("symlink followed")
	}
}
