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

const TYPE_UPDATE = "certificate_update"

var (
	count_updates int = 0
	count_certs int = 0
)

func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	// catch exit so we can print stats
	c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	
	go func() {
        <-c
        cleanup(count_certs, count_updates)
        os.Exit(1)
	}()

	for {
		select {
			case jq := <-stream:
				messageType, err := jq.String("message_type")

				if err != nil{
					log.Fatal("Error decoding jq string")
				}

				count_certs++

				// normally "certificate_update"
				if messageType == TYPE_UPDATE {
					count_updates++
				}

				// dump it
				log.Info("Message type -> ", messageType)
				log.Info("recv: ", jq)
      
			case err := <-errStream:
				log.Error(err)
		}
	}
}

// Print stats then exit
func cleanup(count_certs int, count_updates int) {
	log.Error("Caught CTL-C. Exiting now\n")
	log.Info(fmt.Sprintf("Certificates seen: %d", count_certs))
	log.Info(fmt.Sprintf("Updates: %d", count_updates))
}