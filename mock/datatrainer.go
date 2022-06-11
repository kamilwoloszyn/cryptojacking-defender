package mock

import "github.com/kamilwoloszyn/cryptojacking-defender/domain"

type MockedDataTrainer struct {
	MockExtract      func(*[]domain.TrafficStatistic) []domain.TsTrainingData
	MockSaveAsJSON   func(*[]domain.TsTrainingData, string) error
	MockLoadFromJSON func(string) ([]domain.TsTrainingData, error)
	MockSaveAsCSV    func([]domain.TsTrainingData, string) error
	MockReadFromCSV  func() ([]domain.TsTrainingData, error)
}

func (m *MockedDataTrainer) Extract(stats *[]domain.TrafficStatistic) []domain.TsTrainingData {
	if m.MockExtract != nil {
		return m.MockExtract(stats)
	}
	return []domain.TsTrainingData{}
}

func (m *MockedDataTrainer) SaveAsJSON(data *[]domain.TsTrainingData, absPath string) error {
	if m.MockSaveAsJSON != nil {
		return m.MockSaveAsJSON(data, absPath)
	}
	return ErrNotMocked
}

func (m *MockedDataTrainer) LoadFromJSON(absPath string) ([]domain.TsTrainingData, error) {
	if m.MockLoadFromJSON != nil {
		return m.MockLoadFromJSON(absPath)
	}
	return []domain.TsTrainingData{}, ErrNotMocked
}

func (m *MockedDataTrainer) SaveAsCSV(data []domain.TsTrainingData, absPath string) error {
	if m.MockSaveAsCSV != nil {
		return m.MockSaveAsCSV(data, absPath)
	}
	return ErrNotMocked
}

func (m *MockedDataTrainer) ReadFromCSV() ([]domain.TsTrainingData, error) {
	if m.MockReadFromCSV != nil {
		return m.MockReadFromCSV()
	}
	return []domain.TsTrainingData{}, ErrNotMocked
}
