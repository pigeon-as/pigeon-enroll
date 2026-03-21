package action

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// luksRecoveryConfig holds luks-recovery action configuration.
type luksRecoveryConfig struct {
	// Device is the LUKS2 block device (e.g. "/dev/md1").
	Device string `json:"device"`
	// MappedName is the dm-crypt mapped device name (default: "encrypted").
	MappedName string `json:"mapped_name"`
	// KeySlot is the LUKS2 keyslot to add the recovery key to (default: 1).
	KeySlot int `json:"key_slot"`
	// Secret references a derived secret name whose value becomes the recovery passphrase.
	Secret string `json:"secret"`
}

type luksRecovery struct {
	cfg luksRecoveryConfig
}

func newLuksRecovery(raw json.RawMessage) (*luksRecovery, error) {
	var cfg luksRecoveryConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse luks-recovery config: %w", err)
	}
	if cfg.Device == "" {
		return nil, fmt.Errorf("luks-recovery: device is required")
	}
	if cfg.Secret == "" {
		return nil, fmt.Errorf("luks-recovery: secret is required")
	}
	if cfg.MappedName == "" {
		cfg.MappedName = "encrypted"
	}
	if cfg.KeySlot == 0 {
		cfg.KeySlot = 1
	}
	if cfg.KeySlot < 0 {
		return nil, fmt.Errorf("luks-recovery: key_slot must be >= 1")
	}
	return &luksRecovery{cfg: cfg}, nil
}

func (l *luksRecovery) SecretNames() []string {
	return []string{l.cfg.Secret}
}

func (l *luksRecovery) Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error {
	passphrase, ok := secrets[l.cfg.Secret]
	if !ok {
		return fmt.Errorf("luks-recovery: secret %q not found in derived secrets", l.cfg.Secret)
	}

	volumeKey, err := extractVolumeKey(ctx, l.cfg.MappedName)
	if err != nil {
		return err
	}

	if err := addRecoveryKey(ctx, l.cfg.Device, l.cfg.KeySlot, volumeKey, passphrase); err != nil {
		return err
	}
	logger.Info("LUKS recovery key added",
		"device", l.cfg.Device, "key_slot", l.cfg.KeySlot)
	return nil
}

// extractVolumeKey gets the volume key from an open dm-crypt device via dmsetup.
// The device must already be unlocked. Output format:
//
//	0 <sectors> crypt <cipher> <key_hex> <iv_offset> <device> <offset>
func extractVolumeKey(ctx context.Context, mappedName string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "dmsetup", "table", "--showkeys", mappedName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("dmsetup table --showkeys %s: %w\n%s", mappedName, err, out)
	}

	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 5 || fields[2] != "crypt" {
		return nil, fmt.Errorf("unexpected dmsetup output for %s: expected crypt target, got %d fields", mappedName, len(fields))
	}

	keyHex := fields[4]
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("decode volume key hex: %w", err)
	}
	return key, nil
}

// addRecoveryKey adds a recovery passphrase to the specified LUKS2 keyslot.
// Authenticates using the raw volume key (extracted from the open dm-crypt device)
// and sets the new passphrase in the target keyslot.
func addRecoveryKey(ctx context.Context, device string, slot int, volumeKey []byte, passphrase string) error {
	// Write volume key to a temp file, then unlink it immediately so the key
	// never exists as a named file on disk. Reference via /proc/self/fd.
	vkFile, err := os.CreateTemp("", ".luks-vk-*")
	if err != nil {
		return fmt.Errorf("create temp volume key file: %w", err)
	}
	defer vkFile.Close()

	// Remove directory entry immediately — file stays open via fd.
	if err := os.Remove(vkFile.Name()); err != nil {
		return fmt.Errorf("unlink volume key file: %w", err)
	}

	if _, err := vkFile.Write(volumeKey); err != nil {
		return fmt.Errorf("write volume key: %w", err)
	}
	if _, err := vkFile.Seek(0, 0); err != nil {
		return fmt.Errorf("rewind volume key file: %w", err)
	}

	vkPath := fmt.Sprintf("/proc/self/fd/%d", vkFile.Fd())
	cmd := exec.CommandContext(ctx,
		"cryptsetup", "luksAddKey",
		"--volume-key-file", vkPath,
		"--key-slot", strconv.Itoa(slot),
		"--batch-mode",
		device,
	)
	// cryptsetup reads the new passphrase from stdin.
	cmd.Stdin = strings.NewReader(passphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cryptsetup luksAddKey %s (slot %d): %w\n%s", device, slot, err, out)
	}
	return nil
}
