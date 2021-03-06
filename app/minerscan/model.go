package minerscan

import (
	"strings"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

// Minerscan scans for decrypted request/response to detect cryptomining activities
type MinerScanner struct {
	wordList *wordlist.WordListResponse
}

// New(wordList *wordlist.WordList) that returns only MinnerScanner client
// It reads data from WordList
func New(wordList *wordlist.WordListResponse) *MinerScanner {
	return &MinerScanner{
		wordList: wordList,
	}
}

// Scan scans a text in order to get suspicious keyword.
func (mn *MinerScanner) Scan(t *domain.Traffic) int {
	var result int
	for _, itemToScan := range t.Source.Layers.TextData {
		for _, keyword := range mn.wordList.Req {
			if found := strings.Contains(itemToScan, keyword); found {
				result++
			}
		}
		for _, keyword := range mn.wordList.Res {
			if found := strings.Contains(itemToScan, keyword); found {
				result++
			}
		}
	}
	return result
}
