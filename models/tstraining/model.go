package tstraining

import (
	"log"

	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
)

type CryptoJackingState string

const (
	FieldCryptoJackingBehavior    CryptoJackingState = "cyptojacking"
	FieldNonCryptoJackingBehavior CryptoJackingState = "nocryptojacking"
)

// TsLearningData contains all data needed to machine learning
// Fields description:
// - SentMaliciousPacketRatio, RecvMaliciousPacketRatio - Ratio
type TsTrainingData struct {
	SentMaliciousPacketRatio float32
	RecvMaliciousPacketRatio float32
	AvgGapSentRT             float32
	AvgGapRecvRT             float32
	AvgLenSentFrame          float32
	AvgLenRecvFrame          float32
	SendRecvRatio            float32
	ConsideredAs             CryptoJackingState
}

// Extract extracts training data from PacketFlow struct
func Extract(trafficStats *[]packetflow.TrafficStatistic) []TsTrainingData {
	var trainingData []TsTrainingData
	for _, trafficItem := range *trafficStats {
		trainingData = append(trainingData, TsTrainingData{
			SentMaliciousPacketRatio: getMaliciousPacketRatio(trafficItem.MaliciusTrafficStatistic.SentKeywords, trafficItem.SendQty),
			RecvMaliciousPacketRatio: getMaliciousPacketRatio(trafficItem.MaliciusTrafficStatistic.RecvKeywords, trafficItem.RecvQty),
			AvgGapSentRT:             getAvgGapRT(trafficItem.FramesSendRelativeTime),
			AvgGapRecvRT:             getAvgGapRT(trafficItem.FramesRecvRelativeTime),
			AvgLenSentFrame:          getAvgLenFrame(trafficItem.FramesSendRelativeTime),
			AvgLenRecvFrame:          getAvgLenFrame(trafficItem.FramesRecvRelativeTime),
			SendRecvRatio:            getSendRecvRatio(&trafficItem),
			ConsideredAs:             autoCompleteCryptoJackingState(&trafficItem),
		})
	}
	return trainingData
}

func SaveAsJSON(data *[]TsTrainingData) error {
	return nil
}

// AutoCompleteCryptoJackingState is a function that trying to consider if a field ConsideresAs should contain cryptojacking or nocryptojacking value.
// The function is based on SentMaliciousPacketRatio and RecvMaliciousPacketRatio data.
// If this data are greater than 0, then cryptojacking value will be applied.
// Due to simple alghoritm use this with careful.
func autoCompleteCryptoJackingState(statItem *packetflow.TrafficStatistic) CryptoJackingState {
	if statItem.MaliciusTrafficStatistic.RecvKeywords > 0 && statItem.MaliciusTrafficStatistic.SentKeywords > 0 {
		return FieldCryptoJackingBehavior
	}
	return FieldNonCryptoJackingBehavior
}

func getSendRecvRatio(statItem *packetflow.TrafficStatistic) float32 {
	if statItem.RecvQty == 0 {
		log.Println("[WARNING]: getSendRecvRatio: Unexpected recvQty zero value")
		return 0
	}
	return float32(statItem.SendQty) / float32(statItem.RecvQty)
}

func getMaliciousPacketRatio(mPacketQty int, packetQty int) float32 {
	if packetQty == 0 {
		log.Println("[WARNING]: getRecvMaliciousPacketRatio: Unexpected packetQty zero value")
		return 0
	}
	return float32(mPacketQty) / float32(packetQty)
}

func getAvgGapRT(times []float32) float32 {
	if len(times) >= 2 {
		var sumGap float32
		for i := 0; i < len(times)-1; i++ {
			sumGap += getAbs(times[i] - times[i+1])
		}
		return sumGap / float32(len(times))
	}
	if len(times) == 1 {
		return times[0]
	}
	return 0
}

func getAvgLenFrame(items []float32) float32 {
	if len(items) > 0 {
		var sum float32
		for _, item := range items {
			sum += item
		}
		return sum / float32(len(items))
	}
	return 0
}

func getAbs(num float32) float32 {
	if num < 0 {
		return -num
	}
	return num
}
