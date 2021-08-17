package traffic

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
)

type Layers struct {
	IPSrc            string `json:"ip.src"`
	IPDst            string `json:"ip.dst"`
	TLSDecryptedBody string `json:"-"`
	TLSContentType   string `json:"tls.record.content_type"`
	Frame            string `json:"frame"`
	FrameNumber      int32  `json:"-"`
}
type Source struct {
	Layers Layers `json:"layers"`
}
type Traffic struct {
	Index       string `json:"_index"`
	TypeTraffic string `json:"_type"`
	Score       string `json:"_score"`
	Source      Source `json:"_source"`
}

func New() *Traffic {
	return &Traffic{}
}

// ParseFromJSON loads a traffic from a text file, that contain json struct
// terminal command tshark -r traffic.pcap -o "tls.keylog_file: keys2.txt" -Y tls -Px -T json -e ip.src -e ip.dst -e tls.record.content_type -e data-text-lines -e tls.record.content_type -e frame
func ParseFromJSON(jsonFileAbsPath string) ([]Traffic, error) {
	traffic := []Traffic{}
	if len(jsonFileAbsPath) == 0 {
		return []Traffic{}, errors.New("empty file")
	}
	file, err := os.Open(jsonFileAbsPath)
	if err != nil {
		return []Traffic{}, err
	}
	if err := json.NewDecoder(file).Decode(&traffic); err != nil {
		return []Traffic{}, err
	}
	return traffic, nil
}

// MergeWithDecryptedTraffic performs to adding decrypted tls body to traffic. Probably a heavy operation due to copy, but indexing is needed.
func MergeWithDecryptedTraffic(t []Traffic, td []TrafficDecrypted) ([]Traffic, error) {
	if len(td) == 0 {
		return t, errors.New("decrypted traffic is empty")
	}
	for trafficElementIndex, trafficElement := range t {
		for trafficDecryptedElementIndex, trafficDecryptedElement := range td {
			if equal := reflect.DeepEqual(trafficElement.Source.Layers.FrameNumber, trafficDecryptedElement.FrameNumber); equal {
				t[trafficElementIndex].Source.Layers.TLSDecryptedBody = td[trafficDecryptedElementIndex].DecryptedTLS
			}
		}
	}
	return t, nil
}
