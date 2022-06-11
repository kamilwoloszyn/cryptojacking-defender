package config

type Config struct {
	NetworkInterface              string `env:"NETWORK_INTERFACE" envDefault:"enp6s0"`
	TcpDumpFilePath               string `env:"TCPDUMP_ROOT_PATH" envDefault:"/tmp/traffic.pcap"`
	BrowserSSLFilePath            string `env:"BROWSER_SSL_FILE_PATH" envDefault:""`
	ProjectRootPath               string `env:"CD_PATH_PROJECT" envDefault:""`
	ExternalServicesDecryptedJSON string `env:"CD_PATH_PROJECT_EXTERNAL" envDefault:"/tmp/decrypted_json.txt"`
	TrainingCSVPathRelative       string `env:"CD_PATH_PROJECT_RELATIVE_CSVMODEL" envDefault:"/models/dataprocessor/traffic_data.csv"`
	CSVToPredict                  string `env:"CD_PATH_DATA_PREDICT" envDefault:"/tmp/predict.csv"`
	WordlistFilePath              string `env:"WORDLIST_PATH" envDefault:""`
}
