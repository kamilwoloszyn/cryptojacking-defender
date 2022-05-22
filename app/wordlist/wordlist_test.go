package wordlist_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
)

func TestParseWordlistFromFile(t *testing.T) {
	testCases := []struct {
		desc     string
		arg      string
		expected *wordlist.WordList
	}{
		{
			desc: "Correct wordlist path",
			arg:  "/home/kamil/Projects/cryptojacking-defender/static/wordlist_test.txt",
			expected: &wordlist.WordList{
				Req: []string{
					"nonce",
					"result",
				},
				Res: []string{
					"hashes",
					"blob",
					"job",
					"hash",
				},
			},
		},
		{
			desc:     "Wrong wordlist path",
			arg:      "/home/aaa/aaa.txt",
			expected: nil,
		},
	}

	for i, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if result, err := wordlist.ParseFromFile(tC.arg); !reflect.DeepEqual(result, tC.expected) {
				t.Errorf(
					"Got %v, but expected %v with err :%s", result, tC.expected, err.Error(),
				)
			}
			fmt.Printf("[%d/%d]: Success\n", i+1, len(testCases))
		})
	}
}
