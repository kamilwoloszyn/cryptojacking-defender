package packetflow

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/minerscan"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

// Generate generates a traffic statistics with implemented MinerScanner
func Generate(traffic *[]traffic.Traffic, ms *minerscan.MinerScanner) ([]domain.TrafficStatistic, error) {
	trafficStatistic := []domain.TrafficStatistic{}
	for _, trafficItem := range *traffic {
		if complete := isComplete(trafficItem); !complete {
			return trafficStatistic, errors.New("incomplete traffic")
		}
		keywordsQty := ms.Scan(&trafficItem)
		if duplicate, inversed, location := checkIfExistPairInTS(&trafficStatistic, trafficItem.Source.Layers.IPSrc[0], trafficItem.Source.Layers.IPDst[0]); duplicate {
			if inversed {
				trafficStatistic[location].RecvQty++
				trafficStatistic[location].FramesRecvFrameLen = append(trafficStatistic[location].FramesRecvFrameLen, convertStrToInt(trafficItem.Source.Layers.FrameLength[0]))
				trafficStatistic[location].FramesRecvRelativeTime = append(trafficStatistic[location].FramesRecvRelativeTime, convertStrToFloat32(trafficItem.Source.Layers.FrameTimeRelative[0]))
				trafficStatistic[location].MaliciusTrafficStatistic.RecvKeywords += keywordsQty
				continue
			}
			trafficStatistic[location].SendQty++
			trafficStatistic[location].FramesSendFrameLen = append(trafficStatistic[location].FramesSendFrameLen, convertStrToInt(trafficItem.Source.Layers.FrameLength[0]))
			trafficStatistic[location].FramesSendRelativeTime = append(trafficStatistic[location].FramesSendRelativeTime, convertStrToFloat32(trafficItem.Source.Layers.FrameTimeRelative[0]))
			trafficStatistic[location].MaliciusTrafficStatistic.SentKeywords += keywordsQty
			continue
		}
		trafficStatistic = append(trafficStatistic, domain.TrafficStatistic{
			Base: domain.BaseIP{
				SrcIP: trafficItem.Source.Layers.IPSrc[0],
				DstIP: trafficItem.Source.Layers.IPDst[0],
			},
			SendQty:                1,
			RecvQty:                0,
			FramesSendRelativeTime: []float32{convertStrToFloat32(trafficItem.Source.Layers.FrameTimeRelative[0])},
			FramesSendFrameLen: []int{
				convertStrToInt(trafficItem.Source.Layers.FrameLength[0]),
			},
		})
	}
	return trafficStatistic, nil
}

// SelectIP converts trafficStatistic in a way, where selectedIP is always srcIP.
func SelectIP(ts []domain.TrafficStatistic, ipToSelect string) []domain.TrafficStatistic {
	swapIndexes := []int{}
	for i, item := range ts {
		if item.Base.DstIP == ipToSelect {
			swapIndexes = append(swapIndexes, i)
		}
	}
	ts = swapElements(ts, swapIndexes...)
	return ts
}

// checkIfExistPairInTS check whether given pair (addr, addr2) exists in TrafficStatistic. If exists, it returns :
// bool, bool, int - duplicate,inversed, key of duplicate
// If not exists, it returns false,false -1
func checkIfExistPairInTS(ts *[]domain.TrafficStatistic, addr1 string, addr2 string) (bool, bool, int) {
	for key, tsItem := range *ts {
		if tsItem.Base.SrcIP == addr1 && tsItem.Base.DstIP == addr2 {
			return true, false, key
		}
		if tsItem.Base.SrcIP == addr2 && tsItem.Base.DstIP == addr1 {
			return true, true, key
		}
	}
	return false, false, -1
}

func swapElements(ts []domain.TrafficStatistic, indexes ...int) []domain.TrafficStatistic {
	for _, index := range indexes {
		ts[index].Base.SrcIP, ts[index].Base.DstIP = ts[index].Base.DstIP, ts[index].Base.SrcIP
		ts[index].RecvQty, ts[index].SendQty = ts[index].SendQty, ts[index].RecvQty
		ts[index].FramesRecvFrameLen, ts[index].FramesSendFrameLen = ts[index].FramesSendFrameLen, ts[index].FramesRecvFrameLen
		ts[index].FramesRecvRelativeTime, ts[index].FramesSendRelativeTime = ts[index].FramesSendRelativeTime, ts[index].FramesRecvRelativeTime
	}
	return ts
}

// convertStrToFloat converts a string to a  float nummber,
// Be careful ! It Panics!
func convertStrToFloat32(strToParse string) float32 {
	result, err := strconv.ParseFloat(strToParse, 32)
	if err != nil {
		panic(
			fmt.Sprintf(
				"Wrong dataset in traffic data : %v", err.Error(),
			),
		)
	}
	return float32(result)
}

// convertStrToInt converts string into a int number
// Be careful ! It panics!
func convertStrToInt(strToParse string) int {
	result, err := strconv.Atoi(strToParse)
	if err != nil {
		panic(
			fmt.Sprintf(
				"Wrong dataset in traffic data : %v", err.Error(),
			),
		)
	}
	return result
}

func isComplete(item traffic.Traffic) bool {
	if item.Source.Layers.IPSrc[0] != "" &&
		item.Source.Layers.IPDst[0] != "" &&
		item.Source.Layers.FrameTimeRelative[0] != "" &&
		item.Source.Layers.FrameLength[0] != "" {
		return true
	}
	return false
}
