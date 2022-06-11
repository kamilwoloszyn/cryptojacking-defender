package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"

type MockedWordList struct {
	MockParseFromFile func() (*wordlist.WordListResponse, error)
}

func (m *MockedWordList) ParseFromFile() (*wordlist.WordListResponse, error) {
	if m.MockParseFromFile != nil {
		return m.MockParseFromFile()
	}
	return nil, ErrNotMocked
}
