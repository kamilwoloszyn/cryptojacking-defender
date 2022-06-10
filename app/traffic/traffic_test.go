package traffic_test

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/domain"
)

//go:embed traffic_data_test.txt
var JSONFile string

func TestGenerateTrafficStatistcFromJSONString(t *testing.T) {
	testCases := []struct {
		desc     string
		arg      string
		expected []domain.Traffic
	}{
		{
			desc: "Correct JSON file",
			arg:  JSONFile,
			expected: []domain.Traffic{
				{
					Index:       "packets-2021-08-09",
					TypeTraffic: "doc",
					Score:       nil,
					Source: struct {
						Layers struct {
							IPSrc             []string "json:\"ip.src\""
							IPDst             []string "json:\"ip.dst\""
							TLSContentType    []string "json:\"tls.record.content_type\""
							FrameNumber       []string "json:\"frame.number\""
							FrameLength       []string "json:\"frame.len\""
							FrameTime         []string "json:\"frame.time\""
							FrameTimeRelative []string "json:\"frame.time_relative\""
							TextData          []string "json:\"text\""
						} "json:\"layers\""
					}{
						Layers: struct {
							IPSrc             []string "json:\"ip.src\""
							IPDst             []string "json:\"ip.dst\""
							TLSContentType    []string "json:\"tls.record.content_type\""
							FrameNumber       []string "json:\"frame.number\""
							FrameLength       []string "json:\"frame.len\""
							FrameTime         []string "json:\"frame.time\""
							FrameTimeRelative []string "json:\"frame.time_relative\""
							TextData          []string "json:\"text\""
						}{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"142.250.75.3"},
							TLSContentType:    []string{"22"},
							FrameNumber:       []string{"5"},
							FrameLength:       []string{"583"},
							FrameTime:         []string{"Aug  9, 2021 18:34:50.342226000 CEST"},
							FrameTimeRelative: []string{"0.048908000"},
							TextData: []string{
								"Timestamps",
								"Extension: Reserved (GREASE) (len=0)",
								"Extension: server_name (len=34)",
								"Server Name Indication extension",
								"Extension: extended_master_secret (len=0)",
								"Extension: renegotiation_info (len=1)",
								"Renegotiation Info extension",
								"Extension: supported_groups (len=10)",
								"Extension: ec_point_formats (len=2)",
								"Extension: session_ticket (len=0)",
								"Extension: application_layer_protocol_negotiation (len=14)",
								"Extension: status_request (len=5)",
								"Extension: signature_algorithms (len=18)",
								"Extension: signed_certificate_timestamp (len=0)",
								"Extension: key_share (len=43)",
								"Key Share extension",
								"Key Share Entry: Group: Reserved (GREASE), Key Exchange length: 1",
								"Key Share Entry: Group: x25519, Key Exchange length: 32",
								"Extension: psk_key_exchange_modes (len=2)",
								"Extension: supported_versions (len=11)",
								"Extension: compress_certificate (len=3)",
								"Extension: Unknown type 17513 (len=5)",
								"Extension: Reserved (GREASE) (len=1)",
								"Extension: padding (len=182)",
							},
						},
					},
				},
				{
					Index:       "packets-2021-08-09",
					TypeTraffic: "doc",
					Score:       nil,
					Source: struct {
						Layers struct {
							IPSrc             []string "json:\"ip.src\""
							IPDst             []string "json:\"ip.dst\""
							TLSContentType    []string "json:\"tls.record.content_type\""
							FrameNumber       []string "json:\"frame.number\""
							FrameLength       []string "json:\"frame.len\""
							FrameTime         []string "json:\"frame.time\""
							FrameTimeRelative []string "json:\"frame.time_relative\""
							TextData          []string "json:\"text\""
						} "json:\"layers\""
					}{
						Layers: struct {
							IPSrc             []string "json:\"ip.src\""
							IPDst             []string "json:\"ip.dst\""
							TLSContentType    []string "json:\"tls.record.content_type\""
							FrameNumber       []string "json:\"frame.number\""
							FrameLength       []string "json:\"frame.len\""
							FrameTime         []string "json:\"frame.time\""
							FrameTimeRelative []string "json:\"frame.time_relative\""
							TextData          []string "json:\"text\""
						}{
							IPSrc:             []string{"192.168.0.104"},
							IPDst:             []string{"40.114.177.156"},
							TLSContentType:    []string{"22"},
							FrameNumber:       []string{"9"},
							FrameLength:       []string{"583"},
							FrameTime:         []string{"Aug  9, 2021 18:34:50.358905000 CEST"},
							FrameTimeRelative: []string{"0.065587000"},
							TextData: []string{
								"Timestamps",
								"Extension: Reserved (GREASE) (len=0)",
								"Extension: server_name (len=19)",
								"Server Name Indication extension",
								"Extension: extended_master_secret (len=0)",
								"Extension: renegotiation_info (len=1)",
								"Renegotiation Info extension",
								"Extension: supported_groups (len=10)",
								"Extension: ec_point_formats (len=2)",
								"Extension: session_ticket (len=0)",
								"Extension: application_layer_protocol_negotiation (len=14)",
								"Extension: status_request (len=5)",
								"Extension: signature_algorithms (len=18)",
								"Extension: signed_certificate_timestamp (len=0)",
								"Extension: key_share (len=43)",
								"Key Share extension",
								"Key Share Entry: Group: Reserved (GREASE), Key Exchange length: 1",
								"Key Share Entry: Group: x25519, Key Exchange length: 32",
								"Extension: psk_key_exchange_modes (len=2)",
								"Extension: supported_versions (len=11)",
								"Extension: compress_certificate (len=3)",
								"Extension: Unknown type 17513 (len=5)",
								"Extension: Reserved (GREASE) (len=1)",
								"Extension: padding (len=197)",
							},
						},
					},
				},
			},
		},
		{
			desc:     "Wrong text file",
			arg:      "dfdanffnsikfds",
			expected: []domain.Traffic{},
		},
	}

	for i, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			t.Logf("[%d/%d]: Running ...\n", i+1, len(testCases))
			trafficParserService := traffic.NewTrafficParser("")
			if result, err := trafficParserService.ParseFromJSONString(tC.arg); !reflect.DeepEqual(result, tC.expected) {
				t.Errorf(
					"Task %d failed. Got %v, but expected %v \n err : %v", i+1, result, tC.expected, err,
				)
			}

		})
	}
}
