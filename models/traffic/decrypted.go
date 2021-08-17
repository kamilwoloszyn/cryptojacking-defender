package traffic

type IPAddr string

// TrafficDecrypted is for decrypted version of tshark, because tshark doesn't provide dump to json
type TrafficDecrypted struct {
	SrcIP        IPAddr
	DstIP        IPAddr
	DecryptedTLS string
	FrameNumber  int32
}

func ParseFromTsharkOutputFile(absPath string) ([]TrafficDecrypted, error) {
	trafficDecrypted := []TrafficDecrypted{}
	return trafficDecrypted, nil
}
