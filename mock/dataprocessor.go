package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockedDataProcessor struct {
	MockInitialize     func() (float64, error)
	MockEstimate       func() ([]string, error)
	MockPrintStatistic func([]domain.TsTrainingData, []string)
}

func (m *MockedDataProcessor) Initialize() (float64, error) {
	if m.MockInitialize != nil {
		return m.MockInitialize()
	}
	return 0, ErrNotMocked
}

func (m *MockedDataProcessor) Estimate() ([]string, error) {
	if m.MockEstimate != nil {
		return m.MockEstimate()
	}
	return []string{}, ErrNotMocked
}

func (m *MockedDataProcessor) PrintStatistic(data []domain.TsTrainingData, cols []string) {
	if m.MockPrintStatistic != nil {
		m.MockPrintStatistic(data, cols)
	}
}
