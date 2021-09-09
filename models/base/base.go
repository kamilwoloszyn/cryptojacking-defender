package base

// BaseIP contains src and dst IP
type BaseIP struct {
	SrcIP string
	DstIP string
}

type CryptoJackingState string

const (
	FieldCryptoJackingBehavior    CryptoJackingState = "cryptojacking"
	FieldNonCryptoJackingBehavior CryptoJackingState = "nocryptojacking"
)
