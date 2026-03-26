package action

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLuksRecovery_SecretNames(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	a, err := New(Config{Type: "luks-recovery", Body: jsonToBody(t, cfgJSON)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := a.SecretNames()
	if len(names) != 1 || names[0] != "luks_recovery" {
		t.Errorf("SecretNames = %v, want [luks_recovery]", names)
	}
}

func TestLuksRecovery_MissingKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device": "/dev/md1",
		"secret": "luks_recovery",
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	if err == nil {
		t.Fatal("expected error for missing key_slot, got nil")
	}
}

func TestLuksRecovery_CustomKeySlot(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":      "/dev/md1",
		"mapped_name": "data",
		"key_slot":    3,
		"secret":      "luks_recovery",
	})

	a, err := newLuksRecovery(jsonToBody(t, cfgJSON))
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
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	if err == nil {
		t.Fatal("expected error for missing device")
	}
}

func TestLuksRecovery_MissingSecret(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"key_slot": 1,
	})

	_, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestLuksRecovery_MissingSecretInDerived(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"device":   "/dev/md1",
		"secret":   "luks_recovery",
		"key_slot": 1,
	})

	a, err := newLuksRecovery(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newLuksRecovery: %v", err)
	}

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing derived secret")
	}
}
