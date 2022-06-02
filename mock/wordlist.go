package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"

type MockedWordList struct {
	MockParseFromFile func(absPath string) (*wordlist.WordListResponse, error)
}

func (m *MockedWordList) ParseFromFile(absPath string) (*wordlist.WordListResponse, error) {
	if m.MockParseFromFile != nil {
		return m.MockParseFromFile(absPath)
	}
	return nil, ErrNotMocked
}
