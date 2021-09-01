package traffic

import (
	"encoding/json"
	"errors"
	"os"
)

type IPAddr string

// Layers contains needed informations about packet.
type Layers struct {
	IPSrc             []string `json:"ip.src"`
	IPDst             []string `json:"ip.dst"`
	TLSContentType    []string `json:"tls.record.content_type"`
	FrameNumber       []string `json:"frame.number"`
	FrameLength       []string `json:"frame.len"`
	FrameTime         []string `json:"frame.time"`
	FrameTimeRelative []string `json:"frame.time_relative"`
	TextData          []string `json:"text"`
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

// ParseFromJSON loads a traffic from a text file, which contains json struct
// terminal command tshark -r traffic.pcap -o "tls.keylog_file: keys2.txt" -Y tls -Px -T json -e ip.src -e ip.dst -e tls.record.content_type -e data-text-lines -e tls.record.content_type -e frame.number -e frame.len -e frame.time -e frame.time_relative -e text
func ParseFromJSONFile(jsonFileAbsPath string) ([]Traffic, error) {
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

func ParseFromJSONString(JSONStr string) ([]Traffic, error) {
	traffic := []Traffic{}
	if len(JSONStr) == 0 {
		return []Traffic{}, errors.New("empty string")
	}
	if err := json.Unmarshal([]byte(JSONStr), &traffic); err != nil {
		return []Traffic{}, err
	}
	return traffic, nil
}
