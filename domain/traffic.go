package domain

// Traffic contains all info about packet
type Traffic struct {
	Index       string  `json:"_index"`
	TypeTraffic string  `json:"_type"`
	Score       *string `json:"_score"`
	Source      struct {
		Layers struct {
			IPSrc             []string `json:"ip.src"`
			IPDst             []string `json:"ip.dst"`
			TLSContentType    []string `json:"tls.record.content_type"`
			FrameNumber       []string `json:"frame.number"`
			FrameLength       []string `json:"frame.len"`
			FrameTime         []string `json:"frame.time"`
			FrameTimeRelative []string `json:"frame.time_relative"`
			TextData          []string `json:"text"`
		} `json:"layers"`
	} `json:"_source"`
}
