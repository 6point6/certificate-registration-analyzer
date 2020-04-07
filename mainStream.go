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
	"time"

	"github.com/CaliDog/certstream-go"
	"github.com/jmoiron/jsonq"
)

const typeUpdate = "certificate_update"

var (
	// Global counts printed before exit in cleanup
	countUpdates   int
	countCertsSeen int
	countErrors    int
	start          time.Time

	// slice in which we store the details
	certificates []certDetails
)

type certDetails struct {
	commonName     string
	aggregatedName string
	updateType     string
	fingerprint    string
	validation     string
}

func main() {
	filterPtr := flag.String("filter", "", "Filter term for certificate common name")
	tldPtr := flag.String("tld", "", "Top Level Domain to filter")
	hosePtr := flag.Bool("hose", false, "show the raw stream")

	// args
	flag.Parse()

	if !*hosePtr {
		log.Printf("Using filter %q", *filterPtr)
	} else {
		log.Printf("Outputting unfiltered stream")
	}

	if *tldPtr != "" {
		log.Printf("Using TLD filter %q", *tldPtr)
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
		elapsed := time.Since(start)
		log.Printf("Ran for %s", elapsed.String())

		printFinalStats()
		os.Exit(1)
	}()

	// kickoff timer, run indefinitely
	start = time.Now()

	for {
		select {
		case jq := <-stream:
			countCertsSeen++

			// get common name only, to check filters
			cn, err := getCNFromJSON(jq)

			if err == nil {

				// if in hosepipe mode print all certs
				if *hosePtr {

					// get certificate details
					details, err := getCertDetailsFromJSON(jq)

					// print if processed properly
					if err == nil {
						log.Printf("Type: %q, Subject: %q, Aggregated: %q, Validation: %q, Fingerprint: %q", details.updateType, details.commonName, details.aggregatedName, details.validation, details.fingerprint)
					} else {
						countErrors++
					}
				} else {
					// else in filtered mode, check CN matches filter(s)
					if (*filterPtr == "" || strings.Contains(cn, *filterPtr)) && (*tldPtr == "" || strings.HasSuffix(cn, *tldPtr)) {

						details, err := getCertDetailsFromJSON(jq)

						// print if processed properly
						if err == nil {
							log.Printf("Type: %q, Subject: %q, Aggregated: %q, Validation: %q", details.updateType, details.commonName, details.aggregatedName, details.validation)
							certificates = append(certificates, details)
						} else {
							countErrors++
						}
					}
				}
			} else {
				//log.Printf("Error in processing: %q", err)
				countErrors++
			}

		case err := <-errStream:
			log.Printf("Error in stream: %q", err)
			countErrors++
		}
	}
}

// Take a jq response, return just the CommonName from the Cert
func getCNFromJSON(jq jsonq.JsonQuery) (string, error) {

	// get the CN from the map
	cn, err := jq.String("data", "leaf_cert", "subject", "CN")

	// if we've no errors, stick the values in the struct
	if err == nil {
		return cn, nil
	} else {
		// else return the struct and an error
		return "", fmt.Errorf("JSON Processing Failed")
	}
}

// Take a jq response, parse out the details we care about
func getCertDetailsFromJSON(jq jsonq.JsonQuery) (certDetails, error) {
	var details certDetails

	// get the details from the map, in a clunky fashion
	updateType, err := jq.String("data", "update_type")
	commonName, err2 := jq.String("data", "leaf_cert", "subject", "CN")
	aggregated, err3 := jq.String("data", "leaf_cert", "subject", "aggregated")
	fingerprint, err4 := jq.String("data", "leaf_cert", "fingerprint")
	policies, err5 := jq.String("data", "leaf_cert", "extensions", "certificatePolicies")

	// if we've no errors, stick the values in the struct
	if err == nil && err2 == nil && err3 == nil && err4 == nil && err5 == nil {
		details.commonName = commonName
		details.updateType = updateType
		details.aggregatedName = aggregated
		details.fingerprint = fingerprint
		details.validation = GetCertValidationType(policies)
	} else {
		// else return the struct and an error
		return details, fmt.Errorf("JSON Processing Failed")
	}

	return details, nil
}

// Print stats then exit
func printFinalStats() {
	log.Println("Final stats:")
	log.Printf("Certificates seen: %d", countCertsSeen)
	//log.Printf("Updates: %d", countUpdates)
	log.Printf("Matched: %d", len(certificates))
	log.Printf("Error in processing: %d\n", countErrors)

	// print all saved certs
	writer := new(tabwriter.Writer)

	// Format in tab-separated columns with a tab stop of 8, padding of 4.
	writer.Init(os.Stdout, 0, 8, 4, '\t', 0)
	fmt.Fprintln(writer, "\nCount\tSubject\tAggregated\tUpdate Type\tValidation\tFingerprint")

	for i, cert := range certificates {
		fmt.Fprintf(writer, "%d\t%s\t%s\t%s\t%s\t%s\n", i, cert.commonName, cert.aggregatedName, cert.updateType, cert.validation, cert.fingerprint)
	}

	writer.Flush()
}

// helper function prints the structure
func printStructure(jq jsonq.JsonQuery) {
	dataMap, _ := jq.Object("data")

	for key, value := range dataMap {
		switch t := value.(type) {

		default:
			fmt.Printf("key: %q, type %T\n", key, t)

		case map[string]interface{}:
			fmt.Printf("key: %q, type %T\n", key, t)

			for key2, value2 := range t {
				fmt.Printf("\tkey: %q, type %T\n", key2, value2)
			}
		}
	}
}
