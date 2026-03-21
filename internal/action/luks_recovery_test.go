package action

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLuksRecovery_SecretNames(t *testing.T) {
	cfgJSON, _ := json.Marshal(luksRecoveryConfig{
		Device:  "/dev/md1",
		Secret:  "luks_recovery",
		KeySlot: 1,
	})

	a, err := New(Config{Type: "luks-recovery", Config: cfgJSON})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := a.SecretNames()
	if len(names) != 1 || names[0] != "luks_recovery" {
		t.Errorf("SecretNames = %v, want [luks_recovery]", names)
	}
}

func TestLuksRecovery_MissingKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(luksRecoveryConfig{
		Device: "/dev/md1",
		Secret: "luks_recovery",
	})

	_, err := newLuksRecovery(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing key_slot, got nil")
	}
}

func TestLuksRecovery_CustomKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(luksRecoveryConfig{
		Device:     "/dev/md1",
		MappedName: "data",
		KeySlot:    3,
		Secret:     "luks_recovery",
	})

	a, err := newLuksRecovery(cfgJSON)
	if err != nil {
		t.Fatalf("newLuksRecovery: %v", err)
	}
	if a.cfg.KeySlot != 3 {
		t.Errorf("KeySlot = %d, want 3", a.cfg.KeySlot)
	}
	if a.cfg.MappedName != "data" {
		t.Errorf("MappedName = %q, want %q", a.cfg.MappedName, "data")
	}
}

func TestLuksRecovery_MissingDevice(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]string{
		"secret": "luks_recovery",
	})

	_, err := newLuksRecovery(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing device")
	}
}

func TestLuksRecovery_MissingSecret(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]string{
		"device": "/dev/md1",
	})

	_, err := newLuksRecovery(cfgJSON)
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestLuksRecovery_MissingSecretInDerived(t *testing.T) {
	cfgJSON, _ := json.Marshal(luksRecoveryConfig{
		Device:  "/dev/md1",
		Secret:  "luks_recovery",
		KeySlot: 1,
	})

	a, err := newLuksRecovery(cfgJSON)
	if err != nil {
		t.Fatalf("newLuksRecovery: %v", err)
	}

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing derived secret")
	}
}
