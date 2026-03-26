package render

import "testing"

func TestLookupUserEmpty(t *testing.T) {
	id, err := LookupUser("")
	if err != nil {
		t.Fatal(err)
	}
	if id != -1 {
		t.Fatalf("got %d, want -1", id)
	}
}

func TestLookupUserNumeric(t *testing.T) {
	id, err := LookupUser("1000")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1000 {
		t.Fatalf("got %d, want 1000", id)
	}
}

func TestLookupGroupEmpty(t *testing.T) {
	id, err := LookupGroup("")
	if err != nil {
		t.Fatal(err)
	}
	if id != -1 {
		t.Fatalf("got %d, want -1", id)
	}
}

func TestLookupGroupNumeric(t *testing.T) {
	id, err := LookupGroup("1000")
	if err != nil {
		t.Fatal(err)
	}
	if id != 1000 {
		t.Fatalf("got %d, want 1000", id)
	}
}

func TestChownNoop(t *testing.T) {
	// chown with -1,-1 should be a no-op (no file needed).
	if err := chown("/nonexistent", -1, -1); err != nil {
		t.Fatal(err)
	}
}
