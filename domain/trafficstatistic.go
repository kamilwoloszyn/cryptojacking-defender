package domain

// TrafficStatistic which contain some information for cryptojacking detection.
type TrafficStatistic struct {
	Base                     BaseIP
	SendQty                  int
	RecvQty                  int
	FramesSendRelativeTime   []float32
	FramesRecvRelativeTime   []float32
	FramesSendFrameLen       []int
	FramesRecvFrameLen       []int
	MaliciusTrafficStatistic struct {
		SentKeywords int
		RecvKeywords int
	}
}
