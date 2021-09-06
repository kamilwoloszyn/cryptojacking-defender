package minerscan_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/minerscan"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/wordlist"
)

func TestScan(t *testing.T) {
	wordList, err := wordlist.ParseFromFile("/home/kamil/Projects/cryptojacking-defender/static/wordlist_test.txt")
	if err != nil {
		t.Error(err)
	}
	minerScanner := minerscan.New(wordList)
	testCases := []struct {
		desc     string
		arg      traffic.Traffic
		expected int
	}{
		{
			arg: traffic.Traffic{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             []string{"54.192.230.21"},
						IPDst:             []string{"192.168.0.104"},
						FrameNumber:       []string{"823"},
						FrameLength:       []string{"1454"},
						FrameTime:         []string{"Aug 10, 2021 20:11:04.533162000 CEST"},
						FrameTimeRelative: []string{"3.348897000"},
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
						IPSrc:             []string{"192.168.0.104"},
						IPDst:             []string{"54.192.230.21"},
						FrameNumber:       []string{"845"},
						FrameLength:       []string{"1454"},
						FrameTime:         []string{"Aug 10, 2021 20:11:04.563212000 CEST"},
						FrameTimeRelative: []string{"3.378947000"},
						TextData: []string{
							"Timestamps",
							"{\"type\":\"submit\",\"params\":{\"job_id\":\"xn5w6DxHT4M5Tpg+zUK7YJmdUGri\",\"nonce\":\"88975e1d\",\"result\":\"130193af6f62e2a9688f92b3e297d3d169d7c4047f14f6ec91a764e253320400\"}}",
						},
					},
				},
			},
			expected: 3,
		},
		{
			arg: traffic.Traffic{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             []string{"192.168.0.104"},
						IPDst:             []string{"54.192.230.28"},
						FrameNumber:       []string{"845"},
						FrameLength:       []string{"1454"},
						FrameTime:         []string{"Aug 10, 2021 20:11:04.563212000 CEST"},
						FrameTimeRelative: []string{"3.378947000"},
						TextData: []string{
							"Timestamps",
						},
					},
				},
			},
			expected: 0,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if result := minerScanner.Scan(&tC.arg); !reflect.DeepEqual(tC.expected, result) {
				t.Error(
					fmt.Sprintf("Got %v but expected:%v ", result, tC.expected),
				)
			}
		})
	}

}
