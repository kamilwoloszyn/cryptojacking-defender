package packetflow_test

import (
	"fmt"
	"reflect"
	"testing"

	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
)

type generateTrafficArgs struct {
	args     []traffic.Traffic
	expected []packetflow.TrafficStatistic
}

type selectIPArgs struct {
	args     []packetflow.TrafficStatistic
	expected []packetflow.TrafficStatistic
}

const (
	myIP = "192.168.0.104"
)

func TestGenerateTrafficStatistc(t *testing.T) {

	args := generateTrafficArgs{
		args: []traffic.Traffic{
			{
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
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.21",
						IPDst:             "192.168.0.104",
						FrameNumber:       845,
						FrameLength:       1454,
						FrameTime:         "Aug 10, 2021 20:11:04.563212000 CEST",
						FrameTimeRelative: 3.378947000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.111",
						IPDst:             "192.168.0.104",
						FrameNumber:       852,
						FrameLength:       128,
						FrameTime:         "Aug 10, 2021 20:11:04.563475000 CEST",
						FrameTimeRelative: 3.379210000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.111",
						FrameNumber:       854,
						FrameLength:       97,
						FrameTime:         "Aug 10, 2021 20:11:04.563537000 CEST",
						FrameTimeRelative: 3.379272000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.21",
						IPDst:             "192.168.0.104",
						FrameNumber:       873,
						FrameLength:       1454,
						FrameTime:         "Aug 10, 2021 20:11:04.567367000 CEST",
						FrameTimeRelative: 3.383102000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.111",
						IPDst:             "192.168.0.104",
						FrameNumber:       876,
						FrameLength:       97,
						TLSContentType:    23,
						FrameTime:         "Aug 10, 2021 20:11:04.568167000 CEST",
						FrameTimeRelative: 3.383902000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.21",
						IPDst:             "192.168.0.104",
						FrameNumber:       900,
						FrameLength:       1454,
						FrameTime:         "Aug 10, 2021 20:11:04.574273000 CEST",
						FrameTimeRelative: 3.390008000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.111",
						IPDst:             "192.168.0.104",
						FrameNumber:       907,
						FrameLength:       1043,
						FrameTime:         "Aug 10, 2021 20:11:04.577087000 CEST",
						FrameTimeRelative: 3.392822000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "54.192.230.21",
						IPDst:             "192.168.0.104",
						FrameNumber:       912,
						FrameLength:       1182,
						FrameTime:         "Aug 10, 2021 20:11:04.578005000 CEST",
						FrameTimeRelative: 3.393740000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.21",
						FrameNumber:       931,
						FrameLength:       158,
						FrameTime:         "Aug 10, 2021 20:11:04.652621000 CEST",
						FrameTimeRelative: 3.468356000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.21",
						FrameNumber:       932,
						FrameLength:       97,
						FrameTime:         "Aug 10, 2021 20:11:04.652806000 CEST",
						FrameTimeRelative: 3.468541000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.21",
						FrameNumber:       933,
						FrameLength:       491,
						FrameTime:         "Aug 10, 2021 20:11:04.652850000 CEST",
						FrameTimeRelative: 3.468585000,
					},
				},
			},
			{
				Index:       "packets-2021-08-10",
				TypeTraffic: "doc",
				Score:       nil,
				Source: traffic.Source{
					Layers: traffic.Layers{
						IPSrc:             "192.168.0.104",
						IPDst:             "54.192.230.21",
						FrameNumber:       934,
						FrameLength:       160,
						FrameTime:         "Aug 10, 2021 20:11:04.652917000 CEST",
						FrameTimeRelative: 3.468652000,
					},
				},
			},
		},
		expected: []packetflow.TrafficStatistic{
			{
				SrcIP:                   "54.192.230.21",
				DstIP:                   "192.168.0.104",
				SendQty:                 5,
				RecvQty:                 4,
				CryptoCurrencyPacketQty: 0,
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
				FramesSendFrameLen: []int32{
					1454,
					1454,
					1454,
					1454,
					1182,
				},
				FramesRecvFrameLen: []int32{
					158,
					97,
					491,
					160,
				},
			},
			{
				SrcIP:                   "54.192.230.111",
				DstIP:                   "192.168.0.104",
				SendQty:                 3,
				RecvQty:                 1,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.379210000,
					3.383902000,
					3.392822000,
				},
				FramesRecvRelativeTime: []float32{
					3.379272000,
				},
				FramesSendFrameLen: []int32{
					128,
					97,
					1043,
				},
				FramesRecvFrameLen: []int32{
					97,
				},
			},
			{
				SrcIP:                   "192.168.0.104",
				DstIP:                   "3.23.190.137",
				SendQty:                 1,
				RecvQty:                 0,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.395833000,
				},
				FramesRecvRelativeTime: []float32{},
				FramesSendFrameLen: []int32{
					583,
				},
				FramesRecvFrameLen: []int32{},
			},
		},
	}

	trafficStatistic := packetflow.Generate(&args.args)
	for i, resultItem := range trafficStatistic {
		if equal := reflect.DeepEqual(resultItem, args.expected[i]); !equal {
			t.Fatal(
				fmt.Sprintf(
					"Got %v but expected %v", resultItem, args.expected[i],
				),
			)
		}
	}
}

func TestSelectIP(t *testing.T) {
	args := selectIPArgs{
		args: []packetflow.TrafficStatistic{
			{
				SrcIP:                   "54.192.230.21",
				DstIP:                   "192.168.0.104",
				SendQty:                 2,
				RecvQty:                 3,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.348897000,
					3.378947000,
				},
				FramesRecvRelativeTime: []float32{
					3.468356000,
					3.468541000,
					3.468551000,
				},
				FramesSendFrameLen: []int32{
					1454,
					1454,
				},
				FramesRecvFrameLen: []int32{
					158,
					97,
				},
			},
			{
				SrcIP:                   "54.192.230.111",
				DstIP:                   "192.168.0.104",
				SendQty:                 3,
				RecvQty:                 1,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.379210000,
					3.383902000,
					3.392822000,
				},
				FramesRecvRelativeTime: []float32{
					3.379272000,
				},
				FramesSendFrameLen: []int32{
					128,
					97,
					1043,
				},
				FramesRecvFrameLen: []int32{
					97,
				},
			},
			{
				SrcIP:                   "192.168.0.104",
				DstIP:                   "54.192.230.112",
				SendQty:                 3,
				RecvQty:                 1,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.379210000,
					3.383902000,
					3.392822000,
				},
				FramesRecvRelativeTime: []float32{
					3.379272000,
				},
				FramesSendFrameLen: []int32{
					128,
					97,
					1043,
				},
				FramesRecvFrameLen: []int32{
					97,
				},
			},
		},
		expected: []packetflow.TrafficStatistic{
			{
				SrcIP:                   "192.168.0.104",
				DstIP:                   "54.192.230.21",
				SendQty:                 3,
				RecvQty:                 2,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.468356000,
					3.468541000,
					3.468551000,
				},
				FramesRecvRelativeTime: []float32{
					3.348897000,
					3.378947000,
				},
				FramesSendFrameLen: []int32{
					158,
					97,
				},
				FramesRecvFrameLen: []int32{
					1454,
					1454,
				},
			},
			{
				SrcIP:                   "192.168.0.104",
				DstIP:                   "54.192.230.111",
				SendQty:                 1,
				RecvQty:                 3,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.379272000,
				},
				FramesRecvRelativeTime: []float32{
					3.379210000,
					3.383902000,
					3.392822000,
				},
				FramesSendFrameLen: []int32{
					97,
				},
				FramesRecvFrameLen: []int32{
					128,
					97,
					1043,
				},
			},
			{
				SrcIP:                   "192.168.0.104",
				DstIP:                   "54.192.230.112",
				SendQty:                 3,
				RecvQty:                 1,
				CryptoCurrencyPacketQty: 0,
				FramesSendRelativeTime: []float32{
					3.379210000,
					3.383902000,
					3.392822000,
				},
				FramesRecvRelativeTime: []float32{
					3.379272000,
				},
				FramesSendFrameLen: []int32{
					128,
					97,
					1043,
				},
				FramesRecvFrameLen: []int32{
					97,
				},
			},
		},
	}

	result := packetflow.SelectIP(args.args, myIP)
	for i, resultItem := range result {
		if equal := reflect.DeepEqual(resultItem, args.expected[i]); !equal {
			t.Fatal(
				fmt.Sprintf(
					"got %v but expected %v", resultItem, args.expected[i],
				),
			)
		}
	}
}
