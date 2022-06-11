package main

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/caarlos0/env"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/chrome"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/tcpdump"
	"github.com/kamilwoloszyn/cryptojacking-defender/adapter/tshark"
	"github.com/kamilwoloszyn/cryptojacking-defender/app"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/dataprocessor"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/minerscan"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/packetflow"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/traffic"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/tstraining"
	"github.com/kamilwoloszyn/cryptojacking-defender/app/wordlist"
	"github.com/kamilwoloszyn/cryptojacking-defender/config"
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
	var service *app.Service
	tcpDumpCtx, cancelTcpDump := context.WithCancel(ctx)
	chromeService := chrome.New(cfg.BrowserSSLFilePath)
	tcpdumpService := tcpdump.New(cfg.NetworkInterface, cfg.TcpDumpFilePath)
	tsharkService := tshark.New(cfg.BrowserSSLFilePath)
	dataProcessorService, err := dataprocessor.New(cfg.TrainingCSVPathRelative)
	if err != nil {
		log.Fatalf("couldn't initialize dataprocessor service")
	}
	wordListService := wordlist.NewWordList(cfg.WordlistFilePath)
	wordList, err := wordListService.ParseFromFile()
	if err != nil {
		log.Fatalf("couldn't get a wordlist")
	}
	minerScannerService := minerscan.New(wordList)
	dataTrainerService := tstraining.NewDataTrainer(cfg.TrainingCSVPathRelative, false, true, true, true)
	trafficParserService := traffic.NewTrafficParser(cfg.TcpDumpFilePath)
	trafficStatisticService := packetflow.NewTrafficStatisticsGenerator(service)
	service = app.NewService(
		chromeService,
		tcpdumpService,
		tsharkService,
		dataProcessorService,
		minerScannerService,
		dataTrainerService,
		trafficParserService,
		trafficStatisticService,
		wordListService,
	)
	if err != nil {
		log.Fatalf("[FATAL]:Couldn't initialize some of internal modules: %s ", err.Error())
	}
	// Capturing, decrypting traffic procedure
	log.Println("[INFO]: Starting capturing ...\n [WARNING]: Password may be required for sudo")
	service.TcpDumpCapture(tcpDumpCtx, &wg)
	log.Println("[INFO]: Waiting for a browser .. ")
	if err := service.RunChrome(); err != nil {
		log.Fatalf("[FATAL]: Couldn't run chrome browser: %s. Exiting.", err)
	}
	log.Println("[INFO]: Browser closed. Looking for dump program ...")
	cancelTcpDump()
	wg.Wait()
	log.Println("[INFO]: Fixing corrupted package ...")
	service.FixBrokenPackage(ctx)
	log.Println("[INFO]: Decrypting traffic ...")
	for i := 0; i < 5; i++ {
		err := service.Decrypt(cfg.TcpDumpFilePath, cfg.ExternalServicesDecryptedJSON)
		if err == nil {
			break
		}
		log.Printf("[FATAL]: Couldn't open a decryption program: %s\n", err)
		log.Printf("[INFO]: Probe %d/5 in 10 second ..\n", i+1)
		time.Sleep(time.Second * 10)
	}

	// Processing data
	rawTraffic, err := service.ParseFromJSONFile()
	if err != nil {
		log.Fatalf("[FATAL]:ParseTrafficFromJSONFile: %s\n", err.Error())
	}

	trafficStatistic, err := service.Generate(&rawTraffic)
	if err != nil {
		log.Fatalf("[FATAL]:GenerateTrafficStatistcs: %s\n", err.Error())
	}
	// Training and learning
	trainingData := service.Extract(&trafficStatistic)

	accurancy, err := service.ProcessTrainingData()
	if err != nil {
		log.Printf("[INFO]:Couldn't initialize data processor: %s\n", err.Error())
		err := service.SaveAsCSV(trainingData, cfg.ProjectRootPath+cfg.TrainingCSVPathRelative)
		if err != nil {
			log.Fatalf("[FATAL]: Couldn't save training data: %s", err.Error())
		}
		log.Printf("[INFO]:Nothing to do left. Your train data was saved to: %s\n", cfg.ProjectRootPath+cfg.TrainingCSVPathRelative)
		os.Exit(0)
	}
	log.Printf("[INFO]:Accurancy of trained model: %f", accurancy)
	service.SaveAsCSV(trainingData, cfg.CSVToPredict)
	result, err := service.Estimate(cfg.CSVToPredict)
	if err != nil {
		log.Fatalf("[FATAL]:Couldn't predict a given data: %s", err.Error())
	}
	service.PrintStatistic(trainingData, result)
	log.Println("[INFO]: Cleaning files ...")
	cleanup.RemoveAsCurrentUser(cfg.BrowserSSLFilePath, cfg.TcpDumpFilePath, cfg.CSVToPredict, cfg.ExternalServicesDecryptedJSON)

}
