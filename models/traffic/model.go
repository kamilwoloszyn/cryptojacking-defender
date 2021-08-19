package traffic

type IPAddr string

// TrafficDecrypted is for decrypted version of tshark, because tshark doesn't provide dump to json
type TrafficDecrypted struct {
	SrcIP        IPAddr
	DstIP        IPAddr
	DecryptedTLS string
	FrameNumber  int32
}

// Layers contains needed informations about packet.
type Layers struct {
	IPSrc             string  `json:"ip.src"`
	IPDst             string  `json:"ip.dst"`
	TLSDecryptedBody  string  `json:"-"`
	TLSContentType    int32   `json:"tls.record.content_type"`
	FrameNumber       int32   `json:"frame.number"`
	FrameLength       int32   `json:"frame.len"`
	FrameTime         string  `json:"frame.time"`
	FrameTimeRelative float32 `json:"frame.time_relative"`
}

// Source contains nested Layer body
type Source struct {
	Layers Layers `json:"layers"`
}

// Traffic contains all info about packet
type Traffic struct {
	Index       string  `json:"_index"`
	TypeTraffic string  `json:"_type"`
	Score       *string `json:"_score"`
	Source      Source  `json:"_source"`
}
