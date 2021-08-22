package packetflow

import (
	"github.com/kamilwoloszyn/cryptojacking-defender/models/traffic"
)

// TrafficStatistic which contain some information for cryptojacking detection.
type TrafficStatistic struct {
	SrcIP                   string
	DstIP                   string
	SendQty                 int32
	RecvQty                 int32
	CryptoCurrencyPacketQty int32
	FramesSendRelativeTime  []float32
	FramesRecvRelativeTime  []float32
	FramesSendFrameLen      []int32
	FramesRecvFrameLen      []int32
}

func Generate(traffic *[]traffic.Traffic) []TrafficStatistic {
	trafficStatistic := []TrafficStatistic{}
	for _, trafficItem := range *traffic {
		if duplicate, inversed, location := checkIfExistPairInTS(&trafficStatistic, trafficItem.Source.Layers.IPSrc, trafficItem.Source.Layers.IPDst); duplicate {
			if inversed {
				trafficStatistic[location].RecvQty++
				trafficStatistic[location].FramesRecvFrameLen = append(trafficStatistic[location].FramesRecvFrameLen, trafficItem.Source.Layers.FrameLength)
				trafficStatistic[location].FramesRecvRelativeTime = append(trafficStatistic[location].FramesRecvRelativeTime, trafficItem.Source.Layers.FrameTimeRelative)
				continue
			}
			trafficStatistic[location].SendQty++
			trafficStatistic[location].FramesSendFrameLen = append(trafficStatistic[location].FramesSendFrameLen, trafficItem.Source.Layers.FrameLength)
			trafficStatistic[location].FramesSendRelativeTime = append(trafficStatistic[location].FramesSendRelativeTime, trafficItem.Source.Layers.FrameTimeRelative)
			continue
		}
		trafficStatistic = append(trafficStatistic, TrafficStatistic{
			SrcIP:                   trafficItem.Source.Layers.IPSrc,
			DstIP:                   trafficItem.Source.Layers.IPDst,
			SendQty:                 1,
			RecvQty:                 0,
			CryptoCurrencyPacketQty: 0,
			FramesSendRelativeTime:  []float32{trafficItem.Source.Layers.FrameTimeRelative},
			FramesSendFrameLen: []int32{
				trafficItem.Source.Layers.FrameLength,
			},
		})
	}
	return trafficStatistic
}

func SelectIP(ts []TrafficStatistic, ipToSelect string) []TrafficStatistic {
	swapIndexes := []int{}
	for i, item := range ts {
		if item.DstIP == ipToSelect {
			swapIndexes = append(swapIndexes, i)
		}
	}
	ts = swapElements(ts, swapIndexes...)
	return ts
}

// checkIfExistPairInTS check whether given pair (addr, addr2) exists in TrafficStatistic. If exists, it returns :
// bool, bool, int - duplicate,inversed, key of duplicate
// If not exists, it returns false,false -1
func checkIfExistPairInTS(ts *[]TrafficStatistic, addr1 string, addr2 string) (bool, bool, int) {
	for key, tsItem := range *ts {
		if tsItem.SrcIP == addr1 && tsItem.DstIP == addr2 {
			return true, false, key
		}
		if tsItem.SrcIP == addr2 && tsItem.DstIP == addr1 {
			return true, true, key
		}
	}
	return false, false, -1
}

func swapElements(ts []TrafficStatistic, indexes ...int) []TrafficStatistic {
	for _, index := range indexes {
		ts[index].SrcIP, ts[index].DstIP = ts[index].DstIP, ts[index].SrcIP
		ts[index].RecvQty, ts[index].SendQty = ts[index].SendQty, ts[index].RecvQty
		ts[index].FramesRecvFrameLen, ts[index].FramesSendFrameLen = ts[index].FramesSendFrameLen, ts[index].FramesRecvFrameLen
		ts[index].FramesRecvRelativeTime, ts[index].FramesSendRelativeTime = ts[index].FramesSendRelativeTime, ts[index].FramesRecvRelativeTime
	}
	return ts
}
