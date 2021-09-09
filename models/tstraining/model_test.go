package tstraining_test

import (
	"fmt"
	"os"
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
					AvgGapSentRT:             0.01121074,
					AvgGapRecvRT:             9.870529e-05,
					AvgLenSentFrame:          (1454.0 + 1454.0 + 1454.0 + 1454.0 + 1182.0) / 5.0,
					AvgLenRecvFrame:          226.5,
					SendRecvRatio:            5.0 / 4.0,
					ConsideredAs:             base.FieldCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             0.006806016,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          (128.0 + 97.0 + 1043.0) / 3.0,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3 / 1,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
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

func TestSaveAsJSON(t *testing.T) {
	testCases := []struct {
		desc     string
		arg      []tstraining.TsTrainingData
		expected []tstraining.TsTrainingData
	}{
		{
			desc: "Correct training data",
			arg: []tstraining.TsTrainingData{
				{
					SentMaliciousPacketRatio: 3.0 / 5.0,
					RecvMaliciousPacketRatio: 2.0 / 4.0,
					AvgGapSentRT:             0.01121074,
					AvgGapRecvRT:             9.870529e-05,
					AvgLenSentFrame:          (1454.0 + 1454.0 + 1454.0 + 1454.0 + 1182.0) / 5.0,
					AvgLenRecvFrame:          226.5,
					SendRecvRatio:            5.0 / 4.0,
					ConsideredAs:             base.FieldCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             0.006806016,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          (128.0 + 97.0 + 1043.0) / 3.0,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3 / 1,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
			},
			expected: []tstraining.TsTrainingData{
				{
					SentMaliciousPacketRatio: 3.0 / 5.0,
					RecvMaliciousPacketRatio: 2.0 / 4.0,
					AvgGapSentRT:             0.01121074,
					AvgGapRecvRT:             9.870529e-05,
					AvgLenSentFrame:          (1454.0 + 1454.0 + 1454.0 + 1454.0 + 1182.0) / 5.0,
					AvgLenRecvFrame:          226.5,
					SendRecvRatio:            5.0 / 4.0,
					ConsideredAs:             base.FieldCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             0.006806016,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          (128.0 + 97.0 + 1043.0) / 3.0,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3 / 1,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
			},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if err := tstraining.SaveAsJSON(&tC.arg); err != nil {
				t.Fatalf(
					"Couldn't save JSON: %s", err.Error(),
				)
			}
			result, err := tstraining.LoadFromJSON()
			if err != nil {
				t.Fatalf("Error during loading a file: %s", err)
			}
			if equal := reflect.DeepEqual(result, tC.expected); !equal {
				t.Fatalf(
					"Got %v but expected %v", result, tC.expected,
				)
			}
		})
		t.Cleanup(func() {
			if err := os.Remove("training_data.txt"); err != nil {
				t.Error("Couldn't remove a test file.")
			}
		})
	}
}

func TestSaveReadCSV(t *testing.T) {
	testCases := []struct {
		desc        string
		arg         []tstraining.TsTrainingData
		expected    []tstraining.TsTrainingData
		wantSaveErr bool
		wantReadErr bool
	}{
		{
			desc: "Correct data",
			arg: []tstraining.TsTrainingData{
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             0.006806,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          422.6667,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3.0,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
					ConsideredAs:             base.FieldNonCryptoJackingBehavior,
				},
			},
			expected: []tstraining.TsTrainingData{
				{
					SentMaliciousPacketRatio: 0,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             0.006806,
					AvgGapRecvRT:             3.379272000,
					AvgLenSentFrame:          422.6667,
					AvgLenRecvFrame:          97.0,
					SendRecvRatio:            3.0,
				},
				{
					SentMaliciousPacketRatio: 1,
					RecvMaliciousPacketRatio: 0,
					AvgGapSentRT:             3.395833000,
					AvgGapRecvRT:             0,
					AvgLenSentFrame:          583,
					AvgLenRecvFrame:          0,
					SendRecvRatio:            0,
				},
			},
			wantSaveErr: false,
			wantReadErr: false,
		},
	}

	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if err := tstraining.SaveAsCSV("test_data.csv", tC.arg); !reflect.DeepEqual(err != nil, tC.wantSaveErr) {
				t.Fatalf(
					"Got err: %v, but expected to be %v", err.Error(), tC.wantReadErr,
				)
			}
			if result, err := tstraining.ReadFromCSV(os.TempDir()+"/test_data.csv", true); !reflect.DeepEqual(result, tC.expected) || !reflect.DeepEqual(err != nil, tC.wantReadErr) {
				if (err != nil) != tC.wantReadErr {
					t.Fatalf("Got err: %v, but expected: %v ", err, tC.wantReadErr)
				}
				t.Fatalf("Got %v but expected %v", result, tC.expected)
			}
		})
	}
}
