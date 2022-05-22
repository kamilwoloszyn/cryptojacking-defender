package wordlist

import (
	"bufio"
	"os"

	"github.com/pkg/errors"
)

type WordList struct {
	workingFile string
}

func NewWordList(absPathFile string) *WordList {
	return &WordList{
		workingFile: absPathFile,
	}
}

// Wordlist contains list of reqest or response pattern
type WordListResponse struct {
	Req []string
	Res []string
}
type switchFlag string

const (
	statusRequest  switchFlag = "req"
	statusResponse switchFlag = "res"
)

// ParseFromFile takes absPath to a file, and returns pointer to a wordlist
// If something go bad, then returns nil with error
func (w *WordList) ParseFromFile(absPath string) (*WordListResponse, error) {
	var flag switchFlag
	wList := WordListResponse{
		Req: []string{},
		Res: []string{},
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, errors.Wrapf(err, "Loading wordlist from file")
	}
	fileScanner := bufio.NewScanner(file)
	fileScanner.Split(bufio.ScanLines)
	for fileScanner.Scan() {
		switch word := fileScanner.Text(); word {
		case "req:":
			flag = statusRequest
		case "res:":
			flag = statusResponse
		default:
			if flag == statusRequest {
				wList.Req = append(wList.Req, word)
			}
			if flag == statusResponse {
				wList.Res = append(wList.Res, word)
			}
		}
	}
	return &wList, nil
}
