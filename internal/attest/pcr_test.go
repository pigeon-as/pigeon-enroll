package attest

import "testing"

func TestEvaluatePCRPolicy_Empty(t *testing.T) {
	// Empty policy = log-only mode, always passes.
	if err := EvaluatePCRPolicy(nil, map[int]string{7: "abc"}); err != nil {
		t.Fatal(err)
	}
	if err := EvaluatePCRPolicy(map[string]string{}, map[int]string{7: "abc"}); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluatePCRPolicy_Match(t *testing.T) {
	policy := map[string]string{
		"7":  "aabbccdd",
		"11": "11223344",
	}
	verified := map[int]string{
		7:  "aabbccdd",
		11: "11223344",
	}
	if err := EvaluatePCRPolicy(policy, verified); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluatePCRPolicy_Mismatch(t *testing.T) {
	policy := map[string]string{
		"7": "aabbccdd",
	}
	verified := map[int]string{
		7: "deadbeef",
	}
	err := EvaluatePCRPolicy(policy, verified)
	if err == nil {
		t.Fatal("expected PCR policy violation")
	}
	t.Log(err)
}

func TestEvaluatePCRPolicy_Missing(t *testing.T) {
	policy := map[string]string{
		"7": "aabbccdd",
	}
	verified := map[int]string{} // PCR 7 not in quote
	err := EvaluatePCRPolicy(policy, verified)
	if err == nil {
		t.Fatal("expected error for missing PCR")
	}
	t.Log(err)
}

func TestEvaluatePCRPolicy_InvalidIndex(t *testing.T) {
	policy := map[string]string{
		"abc": "aabbccdd",
	}
	err := EvaluatePCRPolicy(policy, map[int]string{})
	if err == nil {
		t.Fatal("expected error for invalid index")
	}
}

func TestEvaluatePCRPolicy_InvalidHex(t *testing.T) {
	policy := map[string]string{
		"7": "not-hex",
	}
	err := EvaluatePCRPolicy(policy, map[int]string{})
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestEvaluatePCRPolicy_CaseInsensitive(t *testing.T) {
	policy := map[string]string{
		"7": "AABBCCDD",
	}
	verified := map[int]string{
		7: "aabbccdd",
	}
	if err := EvaluatePCRPolicy(policy, verified); err != nil {
		t.Fatalf("expected case-insensitive match: %v", err)
	}
}
