package tshark_test

import (
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/mock"
)

func TestDecrypt(t *testing.T) {

	testCases := []struct {
		description  string
		pcapLocation string
		outputJSON   string
		wantErr      bool
		mockedClient mock.MockedTshark
	}{
		{
			description:  "existing files",
			pcapLocation: "/fake/path/crypto-loot/traffic.pcap",
			outputJSON:   "/fake/path/crypto-loot/decryped-json.txt",
			mockedClient: mock.MockedTshark{
				MockDecrypt: func(s1, s2 string) error {
					return nil
				},
			},
			wantErr: false,
		},
	}

	for _, tC := range testCases {
		t.Run(tC.description, func(t *testing.T) {
			if err := tC.mockedClient.Decrypt(tC.pcapLocation, tC.outputJSON); err != nil {
				t.Fatalf("Got err: %v but expected err to be %v", err, tC.wantErr)
			}
		})
	}
}
