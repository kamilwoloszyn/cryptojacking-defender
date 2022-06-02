package app

import "github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"

type Wordlist interface {
	ParseFromFile(absPath string) (*wordlist.WordListResponse, error)
}
