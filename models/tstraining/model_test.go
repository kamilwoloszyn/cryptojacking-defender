package tstraining_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/base"
	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
	"github.com/kamilwoloszyn/cryptojacking-defender/models/tstraining"
)

func TestExtract(t *testing.T) {
	testCases := []struct {
		desc     string
		arg      []packetflow.TrafficStatistic
		expected []tstraining.TsTrainingData
	}{
		{
			desc: "Correct traffic statistic data",
			arg: []packetflow.TrafficStatistic{
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
					MaliciusTrafficStatistic: struct {
						SentKeywords int
						RecvKeywords int
					}{
						SentKeywords: 3,
						RecvKeywords: 2,
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
					MaliciusTrafficStatistic: struct {
						SentKeywords int
						RecvKeywords int
					}{
						RecvKeywords: 0,
						SentKeywords: 0,
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
					FramesRecvFrameLen: []int{},
					MaliciusTrafficStatistic: struct {
						SentKeywords int
						RecvKeywords int
					}{
						SentKeywords: 1,
						RecvKeywords: 0,
					},
				},
			},
			expected: []tstraining.TsTrainingData{
				{
					SentMaliciousPacketRatio: 3.0 / 5.0,
					RecvMaliciousPacketRatio: 2.0 / 4.0,
					AvgGapSentRT:             ((3.393740000 - 3.390008000) + (3.390008000 - 3.383102000) + (3.383102000 - 3.378947000) + (3.378947000 - 3.348897000)) / 4.0,
					AvgGapRecvRT:             ((3.468652000 - 3.468585000) + (3.468585000 - 3.468541000) + (3.468541000 - 3.468356000)) / 3.0,
					AvgLenSentFrame:          (1454.0 + 1454.0 + 1454.0 + 1454.0 + 1182.0) / 5.0,
					AvgLenRecvFrame:          (158 + 97 + 491 + 160) / 4,
					SendRecvRatio:            5.0 / 4.0,
					ConsideredAs:             tstraining.FieldCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             ((3.392822000 - 3.383902000) + (3.383902000 - 3.379210000)) / 2.0,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          (128.0 + 97.0 + 1043.0) / 3.0,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3 / 1,
					ConsideredAs:             tstraining.FieldNonCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
					ConsideredAs:             tstraining.FieldNonCryptoJackingBehavior,
				},
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if result := tstraining.Extract(&tC.arg); !reflect.DeepEqual(result, tC.expected) {
				t.Fatal(
					fmt.Sprintf(
						"Got %v but expected %v", result, tC.expected,
					),
				)
			}
		})
	}
}
