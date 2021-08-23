package minerscan

import (
	"strings"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/wordlist"
)

// Minerscan scans for decrypted request/response to detect cryptomining activities
type MinerScanner struct {
	wordList *wordlist.WordList
}

func New(wordList *wordlist.WordList) *MinerScanner {
	return &MinerScanner{
		wordList: wordList,
	}
}

// Scan scans a text in order to get suspicious keyword.
func (mn *MinerScanner) Scan(t *traffic.Traffic) int32 {
	var result int32
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
