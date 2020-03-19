package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CaliDog/certstream-go"
)

const typeUpdate = "certificate_update"

// Global counts printed before exit in cleanup
var (
	countUpdates   int
	countCertsSeen int
	countMatch     int
	countErrors    int
)

func main() {
	filterPtr := flag.String("filter", "corona", "Filter term for certificate common name")
	noFilterPtr := flag.Bool("hose", false, "show the raw stream")

	// args
	flag.Parse()

	if !*noFilterPtr {
		if filterPtr == nil {
			log.Println("No filter provided, using default of \"corona\"")
		} else {
			log.Printf("Using provided filter %q", *filterPtr)
		}
	}

	log.Println("Drinking from the hosepipe...")

	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	// catch exit so we can print stats
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Printf("Caught CTL-C. Cleaning up and exiting\n")
		cleanup()
		os.Exit(1)
	}()

	// run indefinitely
	for {
		select {
		case jq := <-stream:
			messageType, err := jq.String("message_type")

			if err != nil {
				log.Fatal("Error decoding jq string")
				countErrors++
			}

			countCertsSeen++

			// normally "certificate_update"
			if messageType == typeUpdate {
				countUpdates++
			}

			// get the details from the map
			// subject:map[C:<nil> CN:hennieyeh.com L:<nil> O:<nil> OU:<nil> ST:<nil> aggregated:/CN=hennieyeh.com]]
			subject, err := jq.Object("data", "leaf_cert", "subject")

			if err == nil {
				commonName := fmt.Sprintf("%v", subject["CN"])
				aggregated := fmt.Sprintf("%v", subject["aggregated"])

				// if in hosepipe mode print all certs
				if *noFilterPtr {
					log.Println(fmt.Sprintf("Message type: %q, Subject: %q, Aggregated: %q", messageType, commonName, aggregated))
				} else if strings.Contains(commonName, *filterPtr) { // else only print matches
					log.Println(fmt.Sprintf("Message type: %q, Subject: %q, Aggregated: %q", messageType, commonName, aggregated))
					countMatch++
				}
			} else {
				log.Println(err)
				countErrors++
			}

		case err := <-errStream:
			log.Println(err)
			countErrors++
		}
	}
}

// Print stats then exit
func cleanup() {
	log.Println("Final stats:")
	log.Printf("Certificates seen: %d", countCertsSeen)
	log.Printf("Updates: %d", countUpdates)
	log.Printf("Matched: %d", countMatch)
	log.Printf("Errored processing: %d", countErrors)
}
