package traffic

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

type IPAddr string

type TrafficParser struct {
	workingFile string
}

func NewTrafficParser(
	workingFile string,
) *TrafficParser {
	return &TrafficParser{
		workingFile: workingFile,
	}
}

// ParseFromJSON loads a traffic from a text file, which contains json struct
func (t *TrafficParser) ParseFromJSONFile() ([]domain.Traffic, error) {
	traffic := []domain.Traffic{}
	if len(t.workingFile) == 0 {
		return []domain.Traffic{}, errors.New("empty file")
	}
	file, err := os.Open(t.workingFile)
	if err != nil {
		return []domain.Traffic{}, err
	}
	if err := json.NewDecoder(file).Decode(&traffic); err != nil {
		return []domain.Traffic{}, err
	}
	return traffic, nil
}

// ParseFromJSONString takes a json string value and returns parsed traffic and error
func (t *TrafficParser) ParseFromJSONString(JSONStr string) ([]domain.Traffic, error) {
	traffic := []domain.Traffic{}
	if len(JSONStr) == 0 {
		return []domain.Traffic{}, errors.New("empty string")
	}
	if err := json.Unmarshal([]byte(JSONStr), &traffic); err != nil {
		return []domain.Traffic{}, err
	}
	return traffic, nil
}
