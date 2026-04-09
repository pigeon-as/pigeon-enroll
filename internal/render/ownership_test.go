package render

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestLookupUserEmpty(t *testing.T) {
	id, err := LookupUser("")
	must.NoError(t, err)
	must.EqOp(t, -1, id)
}

func TestLookupUserNumeric(t *testing.T) {
	id, err := LookupUser("1000")
	must.NoError(t, err)
	must.EqOp(t, 1000, id)
}

func TestLookupGroupEmpty(t *testing.T) {
	id, err := LookupGroup("")
	must.NoError(t, err)
	must.EqOp(t, -1, id)
}

func TestLookupGroupNumeric(t *testing.T) {
	id, err := LookupGroup("1000")
	must.NoError(t, err)
	must.EqOp(t, 1000, id)
}
