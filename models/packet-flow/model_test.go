package packetflow_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/base"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/minerscan"
	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/wordlist"
)

const (
	myIP = "192.168.0.104"
)

func TestGenerateTrafficStatistc(t *testing.T) {
	wordList, err := wordlist.ParseFromFile("/home/kamil/Projects/cryptojacking-defender/static/wordlist_test.txt")
	if err != nil {
		t.Error(err)
	}
	mScan := minerscan.New(wordList)
	testCases := []struct {
		desc     string
		args     []traffic.Traffic
		expected []packetflow.TrafficStatistic
	}{
		{
			desc: "Correct traffic",
			args: []traffic.Traffic{
				{
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
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.21"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"845"},
							FrameLength:       []string{"1454"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.563212000 CEST"},
							FrameTimeRelative: []string{"3.378947000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.111"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"852"},
							FrameLength:       []string{"128"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.563475000 CEST"},
							FrameTimeRelative: []string{"3.379210000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"54.192.230.111"},
							FrameNumber:       []string{"854"},
							FrameLength:       []string{"97"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.563537000 CEST"},
							FrameTimeRelative: []string{"3.379272000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.21"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"873"},
							FrameLength:       []string{"1454"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.567367000 CEST"},
							FrameTimeRelative: []string{"3.383102000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.111"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"876"},
							FrameLength:       []string{"97"},
							TLSContentType:    []string{"23"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.568167000 CEST"},
							FrameTimeRelative: []string{"3.383902000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.21"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"900"},
							FrameLength:       []string{"1454"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.574273000 CEST"},
							FrameTimeRelative: []string{"3.390008000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.111"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"907"},
							FrameLength:       []string{"1043"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.577087000 CEST"},
							FrameTimeRelative: []string{"3.392822000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.21"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"912"},
							FrameLength:       []string{"1182"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.578005000 CEST"},
							FrameTimeRelative: []string{"3.393740000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"54.192.230.21"},
							FrameNumber:       []string{"931"},
							FrameLength:       []string{"158"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.652621000 CEST"},
							FrameTimeRelative: []string{"3.468356000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"54.192.230.21"},
							FrameNumber:       []string{"932"},
							FrameLength:       []string{"97"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.652806000 CEST"},
							FrameTimeRelative: []string{"3.468541000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"54.192.230.21"},
							FrameNumber:       []string{"933"},
							FrameLength:       []string{"491"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.652850000 CEST"},
							FrameTimeRelative: []string{"3.468585000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"54.192.230.21"},
							FrameNumber:       []string{"934"},
							FrameLength:       []string{"160"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.652917000 CEST"},
							FrameTimeRelative: []string{"3.468652000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"3.23.190.137"},
							FrameNumber:       []string{"900"},
							FrameLength:       []string{"583"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.652917001 CEST"},
							FrameTimeRelative: []string{"3.395833000"},
						},
					},
				},
			},
			expected: []packetflow.TrafficStatistic{
				{
					Base: base.BaseIP{
						SrcIP: "54.192.230.21",
						DstIP: "192.168.0.104",
					},
					SendQty: 5,
					RecvQty: 4,
					FramesSendRelativeTime: []float32{
						3.348897000,
						3.378947000,
						3.383102000,
						3.390008000,
						3.393740000,
					},
					FramesRecvRelativeTime: []float32{
						3.468356000,
						3.468541000,
						3.468585000,
						3.468652000,
					},
					FramesSendFrameLen: []int{
						1454,
						1454,
						1454,
						1454,
						1182,
					},
					FramesRecvFrameLen: []int{
						158,
						97,
						491,
						160,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "54.192.230.111",
						DstIP: "192.168.0.104",
					},
					SendQty: 3,
					RecvQty: 1,
					FramesSendRelativeTime: []float32{
						3.379210000,
						3.383902000,
						3.392822000,
					},
					FramesRecvRelativeTime: []float32{
						3.379272000,
					},
					FramesSendFrameLen: []int{
						128,
						97,
						1043,
					},
					FramesRecvFrameLen: []int{
						97,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "192.168.0.104",
						DstIP: "3.23.190.137",
					},
					SendQty: 1,
					RecvQty: 0,
					FramesSendRelativeTime: []float32{
						3.395833000,
					},
					FramesSendFrameLen: []int{
						583,
					},
				},
			},
		},
		{
			desc: "Missing fields traffic",
			args: []traffic.Traffic{
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{""},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"823"},
							FrameLength:       []string{"1454"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.533162000 CEST"},
							FrameTimeRelative: []string{"3.348897000"},
						},
					},
				},
				{
					Index:       "packets-2021-08-10",
					TypeTraffic: "doc",
					Score:       nil,
					Source: traffic.Source{
						Layers: traffic.Layers{
							IPSrc:             []string{"54.192.230.21"},
							IPDst:             []string{"192.168.0.104"},
							FrameNumber:       []string{"845"},
							FrameLength:       []string{"1454"},
							FrameTime:         []string{"Aug 10, 2021 20:11:04.563212000 CEST"},
							FrameTimeRelative: []string{"3.378947000"},
						},
					},
				},
			},
			expected: []packetflow.TrafficStatistic{},
		},
	}
	for i, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			t.Logf("[%d/%d]: Running ...", i+1, len(testCases))
			if result, _ := packetflow.Generate(&tC.args, mScan); !reflect.DeepEqual(result, tC.expected) {
				t.Error(
					fmt.Sprintf(
						"Got %v, but expected %v", result, tC.expected,
					),
				)
			}
		})
	}
}

func TestSelectIP(t *testing.T) {

	testCases := []struct {
		desc     string
		args     []packetflow.TrafficStatistic
		expected []packetflow.TrafficStatistic
	}{
		{
			desc: "Correct ip array",
			args: []packetflow.TrafficStatistic{
				{
					Base: base.BaseIP{
						SrcIP: "54.192.230.21",
						DstIP: "192.168.0.104",
					},
					SendQty: 2,
					RecvQty: 3,
					FramesSendRelativeTime: []float32{
						3.348897000,
						3.378947000,
					},
					FramesRecvRelativeTime: []float32{
						3.468356000,
						3.468541000,
						3.468551000,
					},
					FramesSendFrameLen: []int{
						1454,
						1454,
					},
					FramesRecvFrameLen: []int{
						158,
						97,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "54.192.230.111",
						DstIP: "192.168.0.104",
					},
					SendQty: 3,
					RecvQty: 1,
					FramesSendRelativeTime: []float32{
						3.379210000,
						3.383902000,
						3.392822000,
					},
					FramesRecvRelativeTime: []float32{
						3.379272000,
					},
					FramesSendFrameLen: []int{
						128,
						97,
						1043,
					},
					FramesRecvFrameLen: []int{
						97,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "192.168.0.104",
						DstIP: "54.192.230.112",
					},
					SendQty: 3,
					RecvQty: 1,
					FramesSendRelativeTime: []float32{
						3.379210000,
						3.383902000,
						3.392822000,
					},
					FramesRecvRelativeTime: []float32{
						3.379272000,
					},
					FramesSendFrameLen: []int{
						128,
						97,
						1043,
					},
					FramesRecvFrameLen: []int{
						97,
					},
				},
			},
			expected: []packetflow.TrafficStatistic{
				{
					Base: base.BaseIP{
						SrcIP: "192.168.0.104",
						DstIP: "54.192.230.21",
					},
					SendQty: 3,
					RecvQty: 2,
					FramesSendRelativeTime: []float32{
						3.468356000,
						3.468541000,
						3.468551000,
					},
					FramesRecvRelativeTime: []float32{
						3.348897000,
						3.378947000,
					},
					FramesSendFrameLen: []int{
						158,
						97,
					},
					FramesRecvFrameLen: []int{
						1454,
						1454,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "192.168.0.104",
						DstIP: "54.192.230.111",
					},
					SendQty: 1,
					RecvQty: 3,
					FramesSendRelativeTime: []float32{
						3.379272000,
					},
					FramesRecvRelativeTime: []float32{
						3.379210000,
						3.383902000,
						3.392822000,
					},
					FramesSendFrameLen: []int{
						97,
					},
					FramesRecvFrameLen: []int{
						128,
						97,
						1043,
					},
				},
				{
					Base: base.BaseIP{
						SrcIP: "192.168.0.104",
						DstIP: "54.192.230.112",
					},
					SendQty: 3,
					RecvQty: 1,
					FramesSendRelativeTime: []float32{
						3.379210000,
						3.383902000,
						3.392822000,
					},
					FramesRecvRelativeTime: []float32{
						3.379272000,
					},
					FramesSendFrameLen: []int{
						128,
						97,
						1043,
					},
					FramesRecvFrameLen: []int{
						97,
					},
				},
			},
		},
	}

	for i, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			t.Logf("[%d/%d] Running ...", i+1, len(testCases))
			if result := packetflow.SelectIP(tC.args, myIP); !reflect.DeepEqual(result, tC.expected) {
				t.Fatal(
					fmt.Sprintf("Got %v but expected %v", result, tC.expected),
				)
			}
		})
	}
}
