package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/CaliDog/certstream-go"
)

const typeUpdate = "certificate_update"

var (
	// Global counts printed before exit in cleanup
	countUpdates   int
	countCertsSeen int
	countErrors    int

	// slice in which we store the details
	certificates []certDetails
)

type certDetails struct {
	commonName     string
	aggregatedName string
	updateType     string
	fingerprint    string
}

func main() {
	filterPtr := flag.String("filter", "corona", "Filter term for certificate common name")
	hosePtr := flag.Bool("hose", false, "show the raw stream")

	// args
	flag.Parse()

	if !*hosePtr {
		log.Printf("Using filter %q", *filterPtr)
	} else {
		log.Printf("Outputting unfiltered stream")
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
		printFinalStats()
		os.Exit(1)
	}()

	// run indefinitely
	for {
		select {
		case jq := <-stream:
			countCertsSeen++

			// get the details from the map
			dataMap, err := jq.Object("data")
			subject, err2 := jq.Object("data", "leaf_cert", "subject")
			extensions, err3 := jq.Object("data", "leaf_cert")

			if err == nil && err2 == nil && err3 == nil {
				commonName := fmt.Sprintf("%v", subject["CN"])
				aggregated := fmt.Sprintf("%v", subject["aggregated"])
				updateType := fmt.Sprintf("%v", dataMap["update_type"])
				fingerprint := fmt.Sprintf("%v", extensions["fingerprint"])

				// if in hosepipe mode print all certs
				if *hosePtr {
					log.Printf("Type: %q, Subject: %q, Aggregated: %q", updateType, commonName, aggregated)
				} else if strings.Contains(commonName, *filterPtr) {
					// else only print matches
					log.Printf("Type: %q, Subject: %q, Aggregated: %q", updateType, commonName, aggregated)
					certificates = append(certificates, certDetails{commonName, aggregated, updateType, fingerprint})
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
func printFinalStats() {
	log.Println("Final stats:")
	log.Printf("Certificates seen: %d", countCertsSeen)
	log.Printf("Updates: %d", countUpdates)
	log.Printf("Matched: %d", len(certificates))
	log.Printf("Errored processing: %d\n", countErrors)

	// print all certs
	writer := new(tabwriter.Writer)

	// Format in tab-separated columns with a tab stop of 8, padding of 4.
	writer.Init(os.Stdout, 0, 8, 4, '\t', 0)
	fmt.Fprintln(writer, "\nSubject\tAggregated\tUpdate Type\tFingerprint\t")

	for i, cert := range certificates {
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t\n", i, cert.commonName, cert.aggregatedName, cert.updateType, cert.fingerprint)
	}

	writer.Flush()
}
