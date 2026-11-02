package outer

import (
	"testing"

	"qazwire-audit/r3/sealed/inner"
)

// Foreign type satisfies the "sealed" interface by embedding the interface itself.
type Evil struct{ inner.Protector }

func (Evil) Seal(p []byte) []byte { return []byte("forged") }

func TestR3SealedInterfaceEmbeddingLoophole(t *testing.T) {
	var p inner.Protector = Evil{} // compiles: embedded nil interface promotes sealed()
	got := inner.AcceptsOnlySealed(p)
	if got != "forged" {
		t.Fatal("expected foreign implementation to be accepted")
	}
	t.Log("CONFIRMED: interface with unexported method is NOT sealed against embedding; registry must hand out concrete opaque types")
}
