package dataprocessor_test

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/models/dataprocessor"
)

const (
	PathToCSVDataFile = "/home/kamil/Projects/cryptojacking-defender/models/dataprocessor/traffic_data.csv"
)

func TestInitialize(t *testing.T) {
	testCases := []struct {
		desc    string
		arg     string
		wantErr bool
	}{
		{
			desc:    "existing file path",
			arg:     PathToCSVDataFile,
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
				t.Fatal(
					fmt.Sprintf("Got %v but expected err to be: %v", err, tC.wantErr),
				)
			}
		})
	}
}

func TestPrediction(t *testing.T) {
	dp, err := dataprocessor.New(PathToCSVDataFile)
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
			arg:  "/home/kamil/Projects/cryptojacking-defender/tests/dataprocessor/test_data_1.csv",
			expected: []string{
				"cryptojacking",
				"nocryptojacking",
			},
			wantErr: false,
		},
		{
			desc: "variable data",
			arg:  "/home/kamil/Projects/cryptojacking-defender/tests/dataprocessor/test_data_2.csv",
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
