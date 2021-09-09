package tstraining

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/base"
	packetflow "github.com/kamilwoloszyn/cryptojacking-defender/models/packet-flow"
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
	ConsideredAs             base.CryptoJackingState
	EstimatedBehaviour       base.CryptoJackingState
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
			AvgLenSentFrame:          getAvgLenFrame(trafficItem.FramesSendFrameLen),
			AvgLenRecvFrame:          getAvgLenFrame(trafficItem.FramesRecvFrameLen),
			SendRecvRatio:            getSendRecvRatio(trafficItem.SendQty, trafficItem.RecvQty),
			ConsideredAs:             autoCompleteCryptoJackingState(&trafficItem),
		})
	}
	return trainingData
}

// SaveAsJSON saves training data into a txt file
func SaveAsJSON(data *[]TsTrainingData) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(data); err != nil {
		return fmt.Errorf(
			"couldn't encode JSON: %v", err.Error(),
		)
	}
	os.WriteFile("training_data.txt", buf.Bytes(), 0755)
	return nil
}

func LoadFromJSON() ([]TsTrainingData, error) {
	tData := []TsTrainingData{}
	f, err := os.Open("training_data.txt")
	if err != nil {
		return []TsTrainingData{}, err
	}
	err = json.NewDecoder(f).Decode(&tData)
	if err != nil {
		return []TsTrainingData{}, err
	}
	return tData, nil
}

func SaveAsCSV(name string, data []TsTrainingData) error {
	if name == "" {
		return fmt.Errorf("no name specified")
	}
	if len(data) == 0 {
		return fmt.Errorf("no data provided")
	}
	f, err := os.Create(os.TempDir() + "/" + name)
	if err != nil {
		return fmt.Errorf(
			"could not create tmp file : %s", err.Error(),
		)
	}
	writer := csv.NewWriter(f)
	records := [][]string{
		{
			"sent_malicious_packet_ratio",
			"recv_malicious_packet_ratio",
			"avg_gap_sent_rt",
			"avg_gap_recv_rt",
			"avg_len_sent_frame",
			"avg_len_recv_frame",
			"send_recv_ratio",
			"estimated_behaviour",
		},
	}
	for _, trainingDataItem := range data {
		records = append(records, []string{
			fmt.Sprintf("%f", trainingDataItem.SentMaliciousPacketRatio),
			fmt.Sprintf("%f", trainingDataItem.RecvMaliciousPacketRatio),
			fmt.Sprintf("%f", trainingDataItem.AvgGapSentRT),
			fmt.Sprintf("%f", trainingDataItem.AvgGapRecvRT),
			fmt.Sprintf("%f", trainingDataItem.AvgLenSentFrame),
			fmt.Sprintf("%f", trainingDataItem.AvgLenRecvFrame),
			fmt.Sprintf("%f", trainingDataItem.SendRecvRatio),
		})
	}
	writer.WriteAll(records)
	return nil
}

// ReadFromCSV reads from given path, and returns Training data
func ReadFromCSV(absPath string, containsHeader bool) ([]TsTrainingData, error) {
	trainingData := []TsTrainingData{}
	if absPath == "" {
		return trainingData, fmt.Errorf("ReadFromCSV :path to file is empty")
	}
	file, err := os.Open(absPath)
	if err != nil {
		return trainingData, fmt.Errorf("ReadFromCSV: couldn't read file: %s", err.Error())
	}
	csvReader := csv.NewReader(file)
	csvReader.FieldsPerRecord = -1
	records, err := csvReader.ReadAll()
	if err != nil {
		return trainingData, fmt.Errorf("ReadFromCSV: couldn't get records: %s", err.Error())
	}
	posX := 0
	if containsHeader {
		posX = 1
	}
	for ; posX < len(records); posX++ {
		ok := true
		sentMalPacRatio, err := strconv.ParseFloat(records[posX][0], 32)
		ok = ok && err == nil
		recvMaliciousPacketRatio, err := strconv.ParseFloat(records[posX][1], 32)
		ok = ok && err == nil
		avgGapSentRT, err := strconv.ParseFloat(records[posX][2], 32)
		ok = ok && err == nil
		avgGapRecvRT, err := strconv.ParseFloat(records[posX][3], 32)
		ok = ok && err == nil
		avgLenSentFrame, err := strconv.ParseFloat(records[posX][4], 32)
		ok = ok && err == nil
		avgLenRecvFrame, err := strconv.ParseFloat(records[posX][5], 32)
		ok = ok && err == nil
		sendRecvRatio, err := strconv.ParseFloat(records[posX][6], 32)
		ok = ok && err == nil
		if !ok {
			return trainingData, fmt.Errorf("an error occured during parsing data (str -> float32)")
		}
		trainingData = append(trainingData, TsTrainingData{
			SentMaliciousPacketRatio: float32(sentMalPacRatio),
			RecvMaliciousPacketRatio: float32(recvMaliciousPacketRatio),
			AvgGapSentRT:             float32(avgGapSentRT),
			AvgGapRecvRT:             float32(avgGapRecvRT),
			AvgLenSentFrame:          float32(avgLenSentFrame),
			AvgLenRecvFrame:          float32(avgLenRecvFrame),
			SendRecvRatio:            float32(sendRecvRatio),
		})
	}
	return trainingData, nil
}

// AutoCompleteCryptoJackingState is a function that trying to consider if a field ConsideresAs should contain cryptojacking or nocryptojacking value.
// The function is based on SentMaliciousPacketRatio and RecvMaliciousPacketRatio data.
// If this data are greater than 0, then cryptojacking value will be applied.
// Due to simple alghoritm use this with careful.
func autoCompleteCryptoJackingState(statItem *packetflow.TrafficStatistic) base.CryptoJackingState {
	if statItem.MaliciusTrafficStatistic.RecvKeywords > 0 && statItem.MaliciusTrafficStatistic.SentKeywords > 0 {
		return base.FieldCryptoJackingBehavior
	}
	return base.FieldNonCryptoJackingBehavior
}

func getSendRecvRatio(sentQty int, recvQty int) float32 {
	if recvQty == 0 {
		return 0
	}
	return float32(sentQty) / float32(recvQty)
}

func getMaliciousPacketRatio(mPacketQty int, packetQty int) float32 {
	if packetQty == 0 {
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
		return sumGap / float32(len(times)-1)
	}
	if len(times) == 1 {
		return times[0]
	}
	return 0
}

func getAvgLenFrame(items []int) float32 {
	if len(items) > 0 {
		var sum int
		for _, item := range items {
			sum += item
		}
		return float32(sum) / float32(len(items))
	}
	return 0
}

func getAbs(num float32) float32 {
	if num < 0 {
		return -num
	}
	return num
}
