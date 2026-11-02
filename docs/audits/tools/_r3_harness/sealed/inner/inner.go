package inner

// Sealed-interface pattern proposed for TransportProtector.
type Protector interface {
	Seal(p []byte) []byte
	sealed()
}

type impl struct{}

func (impl) Seal(p []byte) []byte { return append([]byte(nil), p...) }
func (impl) sealed()              {}

func Approved() Protector { return impl{} }

// AcceptsOnlySealed models a registry/device API that trusts the interface type.
func AcceptsOnlySealed(p Protector) string { return string(p.Seal([]byte("x"))) }
