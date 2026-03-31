package attest

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EvaluatePCRPolicy checks verified PCR values against expected golden values.
// If policy is nil or empty, returns nil (log-only mode).
// Each policy key is a PCR index (string), value is expected SHA-256 hex digest.
func EvaluatePCRPolicy(policy map[string]string, verified map[int]string) error {
	if len(policy) == 0 {
		return nil
	}

	var mismatches []string
	for indexStr, expected := range policy {
		var index int
		if _, err := fmt.Sscanf(indexStr, "%d", &index); err != nil {
			return fmt.Errorf("invalid PCR index %q in policy: %w", indexStr, err)
		}

		expectedNorm := strings.ToLower(strings.TrimSpace(expected))
		if _, err := hex.DecodeString(expectedNorm); err != nil {
			return fmt.Errorf("invalid hex value for PCR %d in policy: %w", index, err)
		}

		actual, ok := verified[index]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("PCR %d: not present in quote", index))
			continue
		}

		if actual != expectedNorm {
			mismatches = append(mismatches, fmt.Sprintf("PCR %d: expected %s, got %s", index, expectedNorm, actual))
		}
	}

	if len(mismatches) > 0 {
		return fmt.Errorf("PCR policy violation: %s", strings.Join(mismatches, "; "))
	}
	return nil
}
