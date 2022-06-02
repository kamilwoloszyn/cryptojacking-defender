package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockTrafficParser struct {
	MockParseFromJSONFile   func() ([]domain.Traffic, error)
	MockParseFromJSONString func(string) ([]domain.Traffic, error)
}

func (m *MockTrafficParser) ParseFromJSONFile() ([]domain.Traffic, error) {
	if m.MockParseFromJSONFile != nil {
		return m.MockParseFromJSONFile()
	}
	return []domain.Traffic{}, ErrNotMocked
}

func (m *MockTrafficParser) ParseFromJSONString(absPath string) ([]domain.Traffic, error) {
	if m.MockParseFromJSONString != nil {
		return m.MockParseFromJSONString(absPath)
	}
	return []domain.Traffic{}, ErrNotMocked
}
