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
}

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
		printFinalStats()
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
					log.Printf("Message type: %q, Subject: %q, Aggregated: %q", messageType, commonName, aggregated)
				} else if strings.Contains(commonName, *filterPtr) { // else only print matches
					log.Printf("Message type: %q, Subject: %q, Aggregated: %q", messageType, commonName, aggregated)
					certificates = append(certificates, certDetails{commonName, aggregated})
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
	fmt.Fprintln(writer, "\nSubject\tAggregated\t")

	for _, cert := range certificates {
		fmt.Fprintf(writer, "%s\t%s\t\n", cert.commonName, cert.aggregatedName)
	}

	writer.Flush()
}
