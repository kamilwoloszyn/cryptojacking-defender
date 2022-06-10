package minerscan_test

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/app"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/minerscan"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
	"github.com/kamilwoloszyn/cryptojacking-defender/mock"
)

const (
	PathToWordlistFile = "/test/wordlist/wordlist.txt"
)

var projectPath string = os.Getenv("GOPATH") + "/src/github.com/cryptojacking-defender"

func TestScan(t *testing.T) {
	testCases := []struct {
		desc                  string
		mockedTrafficParserFn func() ([]domain.Traffic, error)
		arg                   traffic.TrafficParser
		expected              int
	}{
		{
			desc: "data frame 1",
			mockedTrafficParserFn: func() ([]domain.Traffic, error) {
				return []domain.Traffic{
					{
						Index:       "packets-2021-08-10",
						TypeTraffic: "doc",
						Score:       nil,
						Source: struct {
							Layers struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							} "json:\"layers\""
						}{
							Layers: struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							}{
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
				}, nil
			},
			expected: 4,
		},
		{
			desc: "data frame 2",
			mockedTrafficParserFn: func() ([]domain.Traffic, error) {
				return []domain.Traffic{
					{
						Index:       "packets-2021-08-10",
						TypeTraffic: "doc",
						Score:       nil,
						Source: struct {
							Layers struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							} "json:\"layers\""
						}{
							Layers: struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							}{
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
				}, nil
			},
			expected: 3,
		},
		{
			desc: "data frame 3",
			mockedTrafficParserFn: func() ([]domain.Traffic, error) {
				return []domain.Traffic{
					{
						Index:       "packets-2021-08-10",
						TypeTraffic: "doc",
						Score:       nil,
						Source: struct {
							Layers struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							} "json:\"layers\""
						}{
							Layers: struct {
								IPSrc             []string "json:\"ip.src\""
								IPDst             []string "json:\"ip.dst\""
								TLSContentType    []string "json:\"tls.record.content_type\""
								FrameNumber       []string "json:\"frame.number\""
								FrameLength       []string "json:\"frame.len\""
								FrameTime         []string "json:\"frame.time\""
								FrameTimeRelative []string "json:\"frame.time_relative\""
								TextData          []string "json:\"text\""
							}{
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
				}, nil
			},
			expected: 0,
		},
		{
			desc: "an err occurred in traffic parser",
			mockedTrafficParserFn: func() ([]domain.Traffic, error) {
				return []domain.Traffic{}, errors.New("oh no, error!")
			},
			expected: 0,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			wordList := wordlist.NewWordList(projectPath + PathToWordlistFile)
			resp, err := wordList.ParseFromFile()
			if err != nil {
				t.Error(err)
			}
			minerScanner := minerscan.New(resp)

			var trafficParser app.TrafficParser = &mock.MockTrafficParser{
				MockParseFromJSONFile:   tC.mockedTrafficParserFn,
				MockParseFromJSONString: nil,
			}

			trafficData, _ := trafficParser.ParseFromJSONFile()

			if result := minerScanner.Scan(
				&trafficData[0],
			); !reflect.DeepEqual(tC.expected, result) {
				t.Error(
					fmt.Sprintf("Got %v but expected:%v ", result, tC.expected),
				)
			}
		})
	}

}
