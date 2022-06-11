package domain

// TsLearningData contains all data needed to machine learning
// Fields description:
// - SentMaliciousPacketRatio, RecvMaliciousPacketRatio - Ratio
type TsTrainingData struct {
	HostsIP                  BaseIP
	SentMaliciousPacketRatio float32
	RecvMaliciousPacketRatio float32
	AvgGapSentRT             float32
	AvgGapRecvRT             float32
	AvgLenSentFrame          float32
	AvgLenRecvFrame          float32
	SendRecvRatio            float32
	ConsideredAs             CryptoJackingState
	EstimatedBehaviour       CryptoJackingState
}
