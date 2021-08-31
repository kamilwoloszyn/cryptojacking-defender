package minerscan_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/minerscan"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/wordlist"
)

type args struct {
	arg      traffic.Traffic
	expected int32
}

func TestScan(t *testing.T) {
	wordList, err := wordlist.ParseFromFile("/home/kamil/Projects/cryptojacking-defender/models/minerscan/wordlist_test.txt")
	if err != nil {
		t.Error(err)
	}
	minerScanner := minerscan.New(wordList)
	testArgs := []args{
		{
			arg: traffic.Traffic{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.21",
						IPDst:             "192.168.0.104",
						FrameNumber:       823,
						FrameLength:       1454,
						FrameTime:         "Aug 10, 2021 20:11:04.533162000 CEST",
						FrameTimeRelative: 3.348897000,
						TextData: []string{
							"Timestamps",
							"{\"type\":\"authed\",\"params\":{\"token\":\"313adf01-9ea8-426c-84b4-7083c7bb5d79\",\"hashes\":0}}",
							"{\"type\":\"job\",\"params\":{\"blob\":\"0c0c93b2c58806a3bffa91a86e77c429203c6b3c8329bfd786656bde139a344feeb9b2327ffe0200000000f5ef11b3efe6a1f01cb4c06816a300b5dfbc5c319d611e5926e9b3b078e4da7b01\",\"job_id\":\"xn5w6DxHT4M5Tpg+zUK7YJmdUGri",
						},
					},
				},
			},
			expected: 4,
		},
		{
			arg: traffic.Traffic{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.21",
						FrameNumber:       845,
						FrameLength:       1454,
						FrameTime:         "Aug 10, 2021 20:11:04.563212000 CEST",
						FrameTimeRelative: 3.378947000,
						TextData: []string{
							"Timestamps",
							"{\"type\":\"submit\",\"params\":{\"job_id\":\"xn5w6DxHT4M5Tpg+zUK7YJmdUGri\",\"nonce\":\"88975e1d\",\"result\":\"130193af6f62e2a9688f92b3e297d3d169d7c4047f14f6ec91a764e253320400\"}}",
						},
					},
				},
			},
			expected: 3,
		},
	}

	for _, tt := range testArgs {
		if result := minerScanner.Scan(&tt.arg); !reflect.DeepEqual(tt.expected, result) {
			t.Error(
				fmt.Sprintf("Got %v but expected:%v ", result, tt.expected),
			)
		}
	}

}
