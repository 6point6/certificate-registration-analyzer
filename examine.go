package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/CaliDog/certstream-go"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("example")

const typeUpdate = "certificate_update"

var (
	countUpdates   int = 0
	countCertsSeen int = 0
)

func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	// catch exit so we can print stats
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		cleanup(countCertsSeen, countUpdates)
		os.Exit(1)
	}()

	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")

			if err != nil {
				log.Fatal("Error decoding jq string")
			}

			countCertsSeen++

			// normally "certificate_update"
			if messageType == typeUpdate {
				countUpdates++
			}

			// dump it
			log.Info(fmt.Sprintf("Message type: %q", messageType))
			//log.Info("recv: ", jq)

			subject, err := jq.Object("data", "leaf_cert", "subject")

			if err == nil {
				// subject:map[C:<nil> CN:hennieyeh.com L:<nil> O:<nil> OU:<nil> ST:<nil> aggregated:/CN=hennieyeh.com]]
				log.Info(fmt.Sprintf("Subject: %q", subject["CN"]))
			}

		case err := <-errStream:
			log.Error(err)
		}
	}
}

// Print stats then exit
func cleanup(countCertsSeen int, countUpdates int) {
	log.Error("Caught CTL-C. Exiting now\n")
	log.Info(fmt.Sprintf("Certificates seen: %d", countCertsSeen))
	log.Info(fmt.Sprintf("Updates: %d", countUpdates))
}
