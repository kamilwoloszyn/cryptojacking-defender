package tshark_test

import (
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/external/tshark"
)

type pcapLocation string

type testDecryptArg struct {
	pcapLocation pcapLocation
}

const (
	sslFilePath = "/home/kamil/Desktop/DiplomaWork/traffic/crypto-loot/keys2.txt"
)

func TestDecrypt(t *testing.T) {
	tshakClient := tshark.New(sslFilePath)
	tsharkArgs := []testDecryptArg{
		{
			pcapLocation: "/home/kamil/Desktop/DiplomaWork/traffic/crypto-loot/traffic.pcap",
		},
	}

	for _, tsharkItem := range tsharkArgs {
		if err := tshakClient.Decrypt(string(tsharkItem.pcapLocation)); err != nil {
			t.Fail()
		}
	}
}
