package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockedDataProcessor struct {
	MockProcessTrainingData func() (float64, error)
	MockEstimate            func(string) ([]string, error)
	MockPrintStatistic      func([]domain.TsTrainingData, []string)
}

func (m *MockedDataProcessor) Initialize() (float64, error) {
	if m.MockProcessTrainingData != nil {
		return m.MockProcessTrainingData()
	}
	return 0, ErrNotMocked
}

func (m *MockedDataProcessor) Estimate(testDataPath string) ([]string, error) {
	if m.MockEstimate != nil {
		return m.MockEstimate(testDataPath)
	}
	return []string{}, ErrNotMocked
}

func (m *MockedDataProcessor) PrintStatistic(data []domain.TsTrainingData, cols []string) {
	if m.MockPrintStatistic != nil {
		m.MockPrintStatistic(data, cols)
	}
}
