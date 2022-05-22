package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/caarlos0/env"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter"
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
	"github.com/kamilwoloszyn/cryptojacking-defender/models"
	"github.com/kamilwoloszyn/cryptojacking-defender/utils/cleanup"
)

func main() {
	var (
		wg sync.WaitGroup
	)
	ctx := context.Background()
	cfg := config.Config{}

	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("[FATAL]: Cannot parse config: %s. Unexpected behavior may occur.", err)
	}
	log.Println("[INFO]: Config loaded succesfully")
	tcpDumpCtx, cancelTcpDump := context.WithCancel(ctx)

	appModules, err := models.InitializeModules(&cfg, &wg)
	if err != nil {
		log.Fatalf("[FATAL]:Couldn't initialize some of internal modules: %s ", err.Error())
	}
	externalServices := adapter.Inititalize(&cfg)

	// Capturing, decrypting traffic procedure
	log.Println("[INFO]: Starting capturing ...\n [WARNING]: Password may be required for sudo")
	externalServices.TcpDump().Capture(tcpDumpCtx, &wg)
	log.Println("[INFO]: Waiting for a browser .. ")
	if err := externalServices.Chrome().Run(); err != nil {
		log.Fatalf("[FATAL]: Couldn't run chrome browser: %s. Exiting.", err)
	}
	log.Println("[INFO]: Browser closed. Looking for dump program ...")
	cancelTcpDump()
	wg.Wait()
	log.Println("[INFO]: Fixing corrupted package ...")
	externalServices.TcpDump().FixBrokenPackage(ctx)
	log.Println("[INFO]: Decrypting traffic ...")
	for i := 0; i < 5; i++ {
		err := externalServices.Tshark().Decrypt(cfg.TcpDumpFilePath, cfg.ExternalServicesDecryptedJSON)
		if err == nil {
			break
		}
		log.Printf("[FATAL]: Couldn't open a decryption program: %s\n", err)
		log.Printf("[INFO]: Probe %d/5 in 10 second ..\n", i+1)
		time.Sleep(time.Second * 10)
	}

	// Processing data
	rawTraffic, err := appModules.ParseTrafficFromJSONFile(cfg.ExternalServicesDecryptedJSON)
	if err != nil {
		log.Fatalf("[FATAL]:ParseTrafficFromJSONFile: %s\n", err.Error())
	}
	trafficStatistic, err := appModules.GenerateTrafficStatistcs(&rawTraffic)
	if err != nil {
		log.Fatalf("[FATAL]:GenerateTrafficStatistcs: %s\n", err.Error())
	}
	// Training and learning
	trainingData := appModules.GenerateTrainingData(&trafficStatistic)

	accurancy, err := appModules.DataProcessor().Initialize()
	if err != nil {
		log.Printf("[INFO]:Couldn't initialize data processor: %s\n", err.Error())
		err := appModules.SaveTrainingData(trainingData, cfg.ProjectRootPath+cfg.TrainingCSVPathRelative, true, false)
		if err != nil {
			log.Fatalf("[FATAL]: Couldn't save training data: %s", err.Error())
		}
		log.Printf("[INFO]:Nothing to do left. Your train data was saved to: %s\n", cfg.ProjectRootPath+cfg.TrainingCSVPathRelative)
		os.Exit(0)
	}
	log.Printf("[INFO]:Accurancy of trained model: %f", accurancy)
	appModules.SaveTrainingData(trainingData, cfg.CSVToPredict, false, true)
	result, err := appModules.DataProcessor().Estimate(cfg.CSVToPredict)
	if err != nil {
		log.Fatalf("[FATAL]:Couldn't predict a given data: %s", err.Error())
	}
	appModules.DataProcessor().PrintStatistic(trainingData, result)
	log.Println("[INFO]: Cleaning files ...")
	cleanup.RemoveAsCurrentUser(cfg.BrowserSSLFilePath, cfg.TcpDumpFilePath, cfg.CSVToPredict, cfg.ExternalServicesDecryptedJSON)

}
