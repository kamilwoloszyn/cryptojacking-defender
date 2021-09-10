package dataprocessor

import (
	"errors"
	"fmt"
	"log"

	"github.com/sjwhitworth/golearn/base"
	"github.com/sjwhitworth/golearn/evaluation"
	"github.com/sjwhitworth/golearn/knn"
)

type DataProcessor struct {
	trainingFileName string
	classifier       *knn.KNNClassifier
}

// New creates a new instance of Dataprocessor. A given filename must exist in the same catalog where this file is.
func New(fileName string) (*DataProcessor, error) {
	if fileName == "" {
		return nil, fmt.Errorf("file name should not be empty")
	}
	return &DataProcessor{
		trainingFileName: fileName,
	}, nil
}

// Initialize parses a training data, make prediction and returns float64 - accurancy, and error
func (dp *DataProcessor) Initialize() (float64, error) {
	rawData, err := base.ParseCSVToInstances(dp.trainingFileName, true)
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
		return 0, fmt.Errorf("initialize(): couldn't get accurancy of your model: %s", err.Error())
	}
	// if accurancy < 0.7 {
	// 	log.Printf("[warning]: accurancy of your model is below 0.7. Expect false positive results.")
	// }
	return accurancy, nil
}

// Estimate takes a data that needs to be predicted, and returns labeled prediction
// Warning: The data should have filled column "estimated_behaviour"  with values cryptojacking and nocryptojacking
// This values won't be taken into account (has no impact on prediction results), an library that makes prediction
// returns an err while this column is empty or have only one of this values
func (dp *DataProcessor) Estimate(absPathToCSVFile string) ([]string, error) {
	results := []string{}
	if dp.classifier == nil {
		return []string{}, fmt.Errorf("Estimate: classifier is empty")
	}
	rawData, err := base.ParseCSVToInstances(absPathToCSVFile, true)
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
