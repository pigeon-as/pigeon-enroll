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
