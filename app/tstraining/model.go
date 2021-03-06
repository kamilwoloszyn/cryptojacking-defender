package tstraining

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

var baseCols = []string{
	"sent_malicious_packet_ratio",
	"recv_malicious_packet_ratio",
	"avg_gap_sent_rt",
	"avg_gap_recv_rt",
	"avg_len_sent_frame",
	"avg_len_recv_frame",
	"send_recv_ratio",
	"estimated_behaviour",
}

type DataTrainer struct {
	workingPath       string
	dryRun            bool
	containsIP        bool
	dataForPrediction bool
	readDataHeader    bool
}

func NewDataTrainer(
	workingPath string,
	dryRun bool,
	containsIP bool,
	dataForPrediction bool,
	readDataHeader bool,
) *DataTrainer {
	return &DataTrainer{
		dryRun: dryRun,
	}
}

// Extract extracts training data from PacketFlow struct
func (d *DataTrainer) Extract(trafficStats *[]domain.TrafficStatistic) []domain.TsTrainingData {
	var trainingData []domain.TsTrainingData
	for _, trafficItem := range *trafficStats {
		trainingData = append(trainingData, domain.TsTrainingData{
			HostsIP:                  trafficItem.Base,
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
func (d *DataTrainer) SaveAsJSON(data *[]domain.TsTrainingData, absPath string) error {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(data); err != nil {
		return fmt.Errorf(
			"couldn't encode JSON: %v", err.Error(),
		)
	}
	if !d.dryRun {
		os.WriteFile(absPath, buf.Bytes(), 0755)
	}
	return nil
}

// LoadFromJSON returns trained data from a specified file.
// If read fails, then returns an empty array with error
func (d *DataTrainer) LoadFromJSON(absPath string) ([]domain.TsTrainingData, error) {
	tData := []domain.TsTrainingData{}
	f, err := os.Open(absPath)
	if err != nil {
		return []domain.TsTrainingData{}, err
	}
	err = json.NewDecoder(f).Decode(&tData)
	if err != nil {
		return []domain.TsTrainingData{}, err
	}
	return tData, nil
}

// SaveAsCSV takes a data and absolute path to a file
// Returns err while something go bad.
// If csv contains IP addr, then should not be used for training model, only for user pourpose
func (d *DataTrainer) SaveAsCSV(data []domain.TsTrainingData, absPath string) error {
	if absPath == "" {
		return fmt.Errorf("no name specified")
	}
	if len(data) == 0 {
		return fmt.Errorf("no data provided")
	}
	var f *os.File
	if !d.dryRun {
		var err error
		f, err = os.Create(absPath)
		if err != nil {
			return fmt.Errorf(
				"could not create a file : %s", err.Error(),
			)
		}
	}
	// It solves "Incopatible attrs while loading a dataset for prediction "
	if d.dataForPrediction {
		data[0].ConsideredAs = "nocryptojacking"
		data[1].ConsideredAs = "cryptojacking"
	}
	writer := csv.NewWriter(f)
	records := [][]string{
		baseCols,
	}
	if d.containsIP {
		cols := append(baseCols, []string{"src_ip", "dst_ip"}...)
		records = [][]string{
			cols,
		}
	}
	if d.containsIP {
		for _, trainingDataItem := range data {
			records = append(records, []string{
				fmt.Sprintf("%f", trainingDataItem.SentMaliciousPacketRatio),
				fmt.Sprintf("%f", trainingDataItem.RecvMaliciousPacketRatio),
				fmt.Sprintf("%f", trainingDataItem.AvgGapSentRT),
				fmt.Sprintf("%f", trainingDataItem.AvgGapRecvRT),
				fmt.Sprintf("%f", trainingDataItem.AvgLenSentFrame),
				fmt.Sprintf("%f", trainingDataItem.AvgLenRecvFrame),
				fmt.Sprintf("%f", trainingDataItem.SendRecvRatio),
				string(trainingDataItem.ConsideredAs),
				string(trainingDataItem.HostsIP.SrcIP),
				string(trainingDataItem.HostsIP.DstIP),
			})
		}
	} else {
		for _, trainingDataItem := range data {
			records = append(records, []string{
				fmt.Sprintf("%f", trainingDataItem.SentMaliciousPacketRatio),
				fmt.Sprintf("%f", trainingDataItem.RecvMaliciousPacketRatio),
				fmt.Sprintf("%f", trainingDataItem.AvgGapSentRT),
				fmt.Sprintf("%f", trainingDataItem.AvgGapRecvRT),
				fmt.Sprintf("%f", trainingDataItem.AvgLenSentFrame),
				fmt.Sprintf("%f", trainingDataItem.AvgLenRecvFrame),
				fmt.Sprintf("%f", trainingDataItem.SendRecvRatio),
				string(trainingDataItem.ConsideredAs),
			})
		}

	}
	if !d.dryRun {
		writer.WriteAll(records)
	}
	return nil
}

// ReadFromCSV reads from given path, and returns Training data
// It takes absPath and info if contains header
// Returns array of training data.
// If something go bad, then returns an empty array with error
// Not suitable for reading model that contain IP fields, only for trained model ready for production !
func (d *DataTrainer) ReadFromCSV() ([]domain.TsTrainingData, error) {
	trainingData := []domain.TsTrainingData{}
	if d.workingPath == "" {
		return trainingData, fmt.Errorf("ReadFromCSV :path to file is empty")
	}
	file, err := os.Open(d.workingPath)
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
	if d.readDataHeader {
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
		trainingData = append(trainingData, domain.TsTrainingData{
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
func autoCompleteCryptoJackingState(statItem *domain.TrafficStatistic) domain.CryptoJackingState {
	if statItem.MaliciusTrafficStatistic.RecvKeywords > 0 && statItem.MaliciusTrafficStatistic.SentKeywords > 0 {
		return domain.FieldCryptoJackingBehavior
	}
	return domain.FieldNonCryptoJackingBehavior
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
