package traffic

import (
	"encoding/json"
	"errors"
	"os"
)

type Layers struct {
	IPSrc          string `json:"ip.src"`
	IPDst          string `json:"ip.dst"`
	TLSContentType string `json:"tls.record.content_type"`
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
func (t *Traffic) ParseFromJSON(jsonFileAbsPath string) error {
	if len(jsonFileAbsPath) == 0 {
		return errors.New("empty file")
	}
	file, err := os.Open(jsonFileAbsPath)
	if err != nil {
		return err
	}
	return json.NewDecoder(file).Decode(t)
}
