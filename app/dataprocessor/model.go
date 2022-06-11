package dataprocessor

import (
	"errors"
	"fmt"
	"log"

	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
	"github.com/sjwhitworth/golearn/base"
	"github.com/sjwhitworth/golearn/evaluation"
	"github.com/sjwhitworth/golearn/knn"
)

type DataProcessor struct {
	trainingFilePath string
	testDataPath     string
	classifier       *knn.KNNClassifier
}

// New creates a new instance of Dataprocessor.
// It takes a training file as an argument.
func New(trainingAbsFilePath string) (*DataProcessor, error) {
	if trainingAbsFilePath == "" {
		return nil, fmt.Errorf("file name should not be empty")
	}
	return &DataProcessor{
		trainingFilePath: trainingAbsFilePath,
	}, nil
}

// ProcessTrainingData parses a training data, make prediction and returns float64 - accurancy, and error
func (dp *DataProcessor) ProcessTrainingData() (float64, error) {
	rawData, err := base.ParseCSVToInstances(dp.trainingFilePath, true)
	if err != nil {
		return 0, fmt.Errorf(
			"couldn't parse csv: %s", err.Error(),
		)
	}
	testData, err := dp.parseData(rawData)
	if err != nil {
		return 0, fmt.Errorf("couldn't learn the dataset correctly: %s", err.Error())
	}
	prediction, err := dp.makePrediction(*testData)
	if err != nil {
		return 0, fmt.Errorf("couldn't make a prediction: %s", err.Error())
	}
	accurancy, err := dp.verifyPrediction(testData, prediction)
	if err != nil {
		return 0, fmt.Errorf("ProcessTrainingData(): couldn't get accurancy of your model: %s", err.Error())
	}
	return accurancy, nil
}

// Estimate takes a data that needs to be predicted, and returns labeled prediction
// Warning: The data should have filled column "estimated_behaviour"  with values cryptojacking and nocryptojacking
// This values won't be taken into account (has no impact on prediction results), an library that makes prediction
// returns an err while this column is empty or have only one of this values
func (dp *DataProcessor) Estimate(testDataPath string) ([]string, error) {
	results := []string{}
	if dp.classifier == nil {
		return []string{}, fmt.Errorf("Estimate: classifier is empty")
	}
	rawData, err := base.ParseCSVToInstances(testDataPath, true)
	if err != nil {
		return []string{}, fmt.Errorf("Estimate: Could not read a given file path")
	}
	prediction, err := dp.classifier.Predict(rawData)
	if err != nil {
		return []string{}, fmt.Errorf("Estimate: Could not predict a given data: %s", err.Error())
	}
	_, rows := prediction.Size()
	for i := 0; i < rows; i++ {
		results = append(results, prediction.RowString(i))
	}
	return results, nil
}

func (dp *DataProcessor) PrintStatistic(trafficStats []domain.TsTrainingData, resultLabels []string) {
	if len(trafficStats) == len(resultLabels) && len(trafficStats) > 0 {
		var cryptojackingCount int
		for k, v := range trafficStats {
			if resultLabels[k] != "cryptojacking" {
				fmt.Printf("\n%s -> %s OK", v.HostsIP.SrcIP, v.HostsIP.DstIP)
			} else {
				fmt.Printf("\n%s -> %s FOUND CRYPTOJACKING\n", v.HostsIP.SrcIP, v.HostsIP.DstIP)
				cryptojackingCount++
			}
		}
		fmt.Printf("\nFound %d cryptojacking connections and %d nocryptojacking connections\n", cryptojackingCount, len(trafficStats)-cryptojackingCount)
	}

}

func (dp *DataProcessor) parseData(rawData *base.DenseInstances) (*base.FixedDataGrid, error) {
	cls := knn.NewKnnClassifier("euclidean", "linear", 2)
	if cls == nil {
		return nil, errors.New("couldn't get KnnClassifier")
	}
	dp.classifier = cls
	trainData, testData := base.InstancesTrainTestSplit(rawData, 0.50)
	cls.Fit(trainData)
	return &testData, nil
}

func (dp *DataProcessor) makePrediction(testData base.FixedDataGrid) (*base.FixedDataGrid, error) {
	prediction, err := dp.classifier.Predict(testData)
	if err != nil {
		return nil, fmt.Errorf(
			"couldn't predict : %s", err.Error(),
		)
	}
	return &prediction, nil
}

func (dp *DataProcessor) verifyPrediction(testData *base.FixedDataGrid, prediction *base.FixedDataGrid) (float64, error) {
	confMatrix, err := evaluation.GetConfusionMatrix(*testData, *prediction)
	if err != nil {
		return 0, fmt.Errorf(
			"couldn't get confusion matrix: %s", err.Error(),
		)
	}
	log.Println(evaluation.GetSummary(confMatrix))
	return evaluation.GetAccuracy(confMatrix), nil
}
