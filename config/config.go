package config

type Config struct {
	NetworkInterface              string `env:"NETWORK_INTERFACE" envDefault:"enp6s0"`
	TcpDumpFilePath               string `env:"TCPDUMP_ROOT_PATH" envDefault:"/tmp/traffic.pcap"`
	BrowserSSLFilePath            string `env:"BROWSER_SSL_FILE_PATH" envDefault:"/tmp/keys.txt"`
	ProjectRootPath               string `env:"CD_PATH_PROJECT" envDefault:"/home/kamil/Projects/cryptojacking-defender"`
	ExternalServicesDecryptedJSON string `env:"CD_PATH_PROJECT_EXTERNAL" envDefault:"/tmp/decrypted_json.txt"`
	TrainingCSVPath               string `env:"CD_PATH_PROJECT_RELATIVE_CSVMODEL" envDefault:"/models/dataprocessor/traffic_data.csv"`
}
