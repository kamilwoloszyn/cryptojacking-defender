package tshark_test

import (
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/external/tshark"
)

const (
	sslFilePath = "/home/kamil/Desktop/DiplomaWork/traffic/crypto-loot/keys2.txt"
)

func TestDecrypt(t *testing.T) {
	tshakClient := tshark.New(sslFilePath)

	testCases := []struct {
		desc         string
		pcapLocation string
		outputJSON   string
		wantErr      bool
	}{
		{
			desc:         "existing files",
			pcapLocation: "/home/kamil/Desktop/DiplomaWork/traffic/crypto-loot/traffic.pcap",
			outputJSON:   "/home/kamil/Desktop/DiplomaWork/traffic/crypto-loot/decryped-json.txt",
			wantErr:      false,
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if err := tshakClient.Decrypt(tC.pcapLocation, tC.outputJSON); err != nil {
				t.Fatalf("Got err: %v but expected err to be %v", err, tC.wantErr)
			}
		})
	}
}
