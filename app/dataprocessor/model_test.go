package dataprocessor_test

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/dataprocessor"
)

const (
	PathToCSVDataFile = "/test/dataprocessor/traffic_data.csv"
	PathToTrainData1  = "/test/dataprocessor/train_data_1.csv"
	PathToTrainData2  = "/test/dataprocessor/train_data_2.csv"
)

var projectPath string = os.Getenv("GOPATH") + "/src/github.com/cryptojacking-defender"

func TestInitialize(t *testing.T) {
	testCases := []struct {
		desc    string
		arg     string
		wantErr bool
	}{
		{
			desc:    "existing file path",
			arg:     projectPath + PathToCSVDataFile,
			wantErr: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			dp, err := dataprocessor.New(tC.arg)
			if err != nil {
				t.Fatalf(
					"Got error %v", err,
				)
			}
			accurancy, err := dp.Initialize()
			fmt.Printf("got  accurancy: %f\n", accurancy)
			if equal := reflect.DeepEqual(isErr(err), tC.wantErr); !equal {
				t.Fatalf("Got %v but expected err to be: %v", err, tC.wantErr)
			}
		})
	}
}

func TestPrediction(t *testing.T) {
	dp, err := dataprocessor.New(projectPath + PathToCSVDataFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dp.Initialize(); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		desc     string
		arg      string
		expected []string
		wantErr  bool
	}{
		{
			desc: "correct train data",
			arg:  projectPath + PathToTrainData1,
			expected: []string{
				"cryptojacking",
				"nocryptojacking",
			},
			wantErr: false,
		},
		{
			desc: "variable data",
			arg:  projectPath + PathToTrainData2,
			expected: []string{
				"cryptojacking",
				"nocryptojacking",
				"cryptojacking",
				"nocryptojacking",
				"cryptojacking",
				"nocryptojacking",
			},
			wantErr: false,
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			if result, err := dp.Estimate(tC.arg); !reflect.DeepEqual(result, tC.expected) || !reflect.DeepEqual(err != nil, tC.wantErr) {
				if (err != nil) != tC.wantErr {
					t.Fatalf("got %v,but expected err to be %v", err, tC.wantErr)
				}
				t.Fatalf("Got %v but expected %v", result, tC.expected)
			}
		})
	}
}

func isErr(err error) bool {
	return err != nil
}
