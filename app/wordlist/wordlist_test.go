package wordlist_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/mock"
)

func TestParseWordlistFromFile(t *testing.T) {
	testCases := []struct {
		desc           string
		expectedResult *wordlist.WordListResponse
		mockedClient   func() (*wordlist.WordListResponse, error)
	}{
		{
			desc: "Correct wordlist path",
			expectedResult: &wordlist.WordListResponse{
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
			mockedClient: func() (*wordlist.WordListResponse, error) {
				return &wordlist.WordListResponse{
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
				}, nil
			},
		},
		{
			desc: "Wrong wordlist path",
			mockedClient: func() (*wordlist.WordListResponse, error) {
				return nil, errors.New("path not found")
			},
			expectedResult: nil,
		},
	}

	for i, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			client := mock.MockedWordList{
				MockParseFromFile: tC.mockedClient,
			}
			if result, err := client.ParseFromFile(); !reflect.DeepEqual(result, tC.expectedResult) {
				t.Errorf(
					"Got %v, but expected %v with err :%s", result, tC.expectedResult, err.Error(),
				)
			}
			fmt.Printf("[%d/%d]: Success\n", i+1, len(testCases))
		})
	}
}
