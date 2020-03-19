package main

import (
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
	countCorona    int
	countErrors    int
)

func main() {
	// The false flag specifies that we want heartbeat messages.
	stream, errStream := certstream.CertStreamEventStream(false)

	// catch exit so we can print stats
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
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

				if strings.Contains(commonName, "corona") {
					log.Println(fmt.Sprintf("Message type: %q, Subject: %q, Aggregated: %q", messageType, commonName, aggregated))
					countCorona++
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
	log.Println("Caught CTL-C. Exiting now")
	log.Printf("Certificates seen: %d", countCertsSeen)
	log.Printf("Updates: %d", countUpdates)
	log.Printf("Corona: %d", countCorona)
	log.Printf("Errored processing: %d", countErrors)
}

/*
Example cert:
2020/03/18 15:51:39 Message type ->  certificate_update
2020/03/18 15:51:39 recv:  {map[data:map[cert_index:1.066256262e+09 cert_link:http://ct.googleapis.com/rocketeer/ct/v1/get-entries?start=1066256262&end=1066256262 chain:[map[as_der:MIIEqjCCA5KgAwIBAgIQAnmsRYvBskWr+YBTzSybsTANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBDQTAeFw0xNzExMjcxMjQ2MTBaFw0yNzExMjcxMjQ2MTBaMG4xCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xLTArBgNVBAMTJEVuY3J5cHRpb24gRXZlcnl3aGVyZSBEViBUTFMgQ0EgLSBHMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALPeP6wkab41dyQh6mKcoHqt3jRIxW5MDvf9QyiOR7VfFwK656es0UFiIb74N9pRntzF1UgYzDGu3ppZVMdolbxhm6dWS9OK/lFehKNT0OYI9aqk6F+U7cA6jxSC+iDBPXwdF4rs3KRyp3aQn6pjpp1yr7IB6Y4zv72Ee/PlZ/6rK6InC6WpK0nPVOYR7n9iDuPe1E4IxUMBH/T33+3hyuH3dvfgiWUOUkjdpMbyxX+XNle5uEIiyBsi4IvbcTCh8ruifCIi5mDXkZrnMT8nwfYCV6v6kDdXkbgGRLKsR4pucbJtbKqIkUGxuZI2t7pfewKRc5nWecvDBZf3+p1MpA8CAwEAAaOCAU8wggFLMB0GA1UdDgQWBBRVdE+yck/1YLpQ0dfmUVyaAYca1zAfBgNVHSMEGDAWgBQD3lA1VtFMu2bwo+IbG8OXsj3RVTAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwBAjAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAECATANBgkqhkiG9w0BAQsFAAOCAQEAK3Gp6/aGq7aBZsxf/oQ+TD/BSwW3AU4ETK+GQf2kFzYZkby5SFrHdPomunx2HBzViUchGoofGgg7gHW0W3MlQAXWM0r5LUvStcr82QDWYNPaUy4taCQmyaJ+VB+6wxHstSigOlSNF2a6vg4rgexixeiV4YSB03Yqp2t3TeZHM9ESfkus74nQyW7pRGezj+TC44xCagCQQOzzNmzEAP2SnCrJsNE2DpRVMnL8J6xBRdjmOsC3N6cQuKuRXbzByVBjCqAA8t1L0I+9wXJerLPyErjyrMKWaBFLmfK/AHNF4ZihwPGOc7w6UHczBZXH5RFzJNnww+WnKuTPI0HfnVH8lg== extensions:map[authorityInfoAccess:OCSP - URI:http://ocsp.digicert.com
 authorityKeyIdentifier:keyid:03:DE:50:35:56:D1:4C:BB:66:F0:A3:E2:1B:1B:C3:97:B2:3D:D1:55
 basicConstraints:CA:TRUE certificatePolicies:Policy: 2.23.140.1.2.1
Policy: 2.16.840.1.114412.1.2
  CPS: https://www.digicert.com/CPS crlDistributionPoints:Full Name:
 URI:http://crl3.digicert.com/DigiCertGlobalRootCA.crl extendedKeyUsage:TLS Web server authentication, TLS Web client authentication keyUsage:Digital Signature, Key Cert Sign, C R L Sign subjectKeyIdentifier:55:74:4F:B2:72:4F:F5:60:BA:50:D1:D7:E6:51:5C:9A:01:87:1A:D7] fingerprint:59:4F:2D:D1:03:52:C2:36:01:38:EE:35:AA:90:6F:97:3A:A3:0B:D3 not_after:1.82731957e+09 not_before:1.51178677e+09 serial_number:279AC458BC1B245ABF98053CD2C9BB1 subject:map[C:US CN:Encryption Everywhere DV TLS CA - G1 L:<nil> O:DigiCert Inc OU:www.digicert.com ST:<nil> aggregated:/C=US/CN=Encryption Everywhere DV TLS CA - G1/O=DigiCert Inc/OU=www.digicert.com]] map[as_der:MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBDQTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsBCSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7PT19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbRTLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUwDQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/EsrhMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJFPnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0lsYSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQkCAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4= extensions:map[authorityKeyIdentifier:keyid:03:DE:50:35:56:D1:4C:BB:66:F0:A3:E2:1B:1B:C3:97:B2:3D:D1:55
 basicConstraints:CA:TRUE keyUsage:Digital Signature, Key Cert Sign, C R L Sign subjectKeyIdentifier:03:DE:50:35:56:D1:4C:BB:66:F0:A3:E2:1B:1B:C3:97:B2:3D:D1:55] fingerprint:A8:98:5D:3A:65:E5:E5:C4:B2:D7:D6:6D:40:C6:DD:2F:B1:9C:54:36 not_after:1.9520352e+09 not_before:1.1631168e+09 serial_number:83BE056904246B1A1756AC95991C74A subject:map[C:US CN:DigiCert
Global Root CA L:<nil> O:DigiCert Inc OU:www.digicert.com ST:<nil> aggregated:/C=US/CN=DigiCert Global Root CA/O=DigiCert Inc/OU=www.digicert.com]]] leaf_cert:map[all_domains:[*.hennieyeh.com hennieyeh.com] as_der:MIIFlDCCBHygAwIBAgIQAqA7mRRn1ae5rFh/5CNnVDANBgkqhkiG9w0BAQsFADBuMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMS0wKwYDVQQDEyRFbmNyeXB0aW9uIEV2ZXJ5d2hlcmUgRFYgVExTIENBIC0gRzEwHhcNMjAwMzEzMDAwMDAwWhcNMjEwMzE0MTIwMDAwWjAYMRYwFAYDVQQDEw1oZW5uaWV5ZWguY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9udRcC373gUmFDXpnAgTHc7es7iCfaakijdJ/dHx6j3ODmusmCfQTU7ZrlybZfLbRttdv2/MXuQhANw71HatzGg2kOvT9gBDnYcv8mfKED7uNs58YHwGkcYwu6fcJKo9NbASbFAHvveQpjIYUnerJylDsp4HlGp2C4opD4+mSmnOxXfvdAu6Tj0hwnquZZigFCmucc8qpfekXE2byvBh8YBIQj01XIN5nsKbAd3uZFiajvYmE0mkWHtWqTw/QzO1qSW0ZQeB6Pj9KGkS+WQIbpbPZxPvk2vA4JMAksvoJb8RCBAWCduzViq24m5MmKrwYqRYvTyg5KTGeP4ANEKrOQIDAQABo4ICgjCCAn4wHwYDVR0jBBgwFoAUVXRPsnJP9WC6UNHX5lFcmgGHGtcwHQYDVR0OBBYEFMaR4MTVzpxfEwHl1WNtObZiD0dlMCkGA1UdEQQiMCCCDWhlbm5pZXllaC5jb22CDyouaGVubmlleWVoLmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMEwGA1UdIARFMEMwNwYJYIZIAYb9bAECMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCAYGZ4EMAQIBMIGABggrBgEFBQcBAQR0MHIwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBKBggrBgEFBQcwAoY+aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0VuY3J5cHRpb25FdmVyeXdoZXJlRFZUTFNDQS1HMS5jcnQwCQYDVR0TBAIwADCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3ALvZ37wfinG1k5Qjl6qSe0c4V5UKq1LoGpCWZDaOHtGFAAABcNQNiacAAAQDAEgwRgIhAMd2PqLESTGDXJi1adOracVia6K2jYdNsg0UnsXk+firAiEApnwg9zdJG6/kKYLmcw0DyAmy9RXHuGLXTAWjAZw3X9kAdQBc3EOS/uarRUSxXprUVuYQN/vV+kfcoXOUsl7m9scOygAAAXDUDYn9AAAEAwBGMEQCIEWQ9aUlSe5uWAtFqEqluStjO5XFytnXSZcfC5MQdDM8AiAb7ASVQTwxTnWTfmoV9zKNxczBfeFTYlv8uW/GqVj3qTANBgkqhkiG9w0BAQsFAAOCAQEAiVKgSajl5EPQB9CdNbv0b7EsgAJMLLzdgwVA3Hf5lRWjOqTQA8CeWp4kSb2YuNIKuiARyBnYkYBnAat27XyvJDaKCEwY4gdDyPWhW0L9mIBi+Jxj1k5pqqDqtYyRARXUAD2qBAOGOklELns1LcUWyEbZmooIEIgWAvExVM4fperojjeac3uZ4EDM7v8IkHoSMs3akIP2vEoS6h1IgCVnNyo1rWLcHI9HL7R3TLx8jhRejZMb8i1gYXGG8MoFKbrieRhs8LqLSdXrzcgZCkG4bf/YFQvT/5MWbeNs8RFRZ6ChpYGh+40+wNQakiTV4uAcdqejypGk1Y9hOEZfgY3RkQ== extensions:map[authorityInfoAccess:CA Issuers - URI:http://cacerts.digicert.com/EncryptionEverywhereDVTLSCA-G1.crt
OCSP - URI:http://ocsp.digicert.com
 authorityKeyIdentifier:keyid:55:74:4F:B2:72:4F:F5:60:BA:50:D1:D7:E6:51:5C:9A:01:87:1A:D7
 basicConstraints:CA:FALSE certificatePolicies:Policy: 2.23.140.1.2.1
Policy: 2.16.840.1.114412.1.2
  CPS: https://www.digicert.com/CPS ctlSignedCertificateTimestamp:BIHyAPAAdwC72d-8H4pxtZOUI5eqkntHOFeVCqtS6BqQlmQ2jh7RhQAAAXDUDYmnAAAEAwBIMEYCIQDHdj6ixEkxg1yYtWnTq2nFYmuito2HTbINFJ7F5Pn4qwIhAKZ8IPc3SRuv5CmC5nMNA8gJsvUVx7hi10wFowGcN1_ZAHUAXNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDsoAAAFw1A2J_QAABAMARjBEAiBFkPWlJUnublgLRahKpbkrYzuVxcrZ10mXHwuTEHQzPAIgG-wElUE8MU51k35qFfcyjcXMwX3hU2Jb_LlvxqlY96k= extendedKeyUsage:TLS Web server authentication, TLS Web client authentication keyUsage:Digital Signature, Key Encipherment subjectAltName:DNS:*.hennieyeh.com, DNS:hennieyeh.com subjectKeyIdentifier:C6:91:E0:C4:D5:CE:9C:5F:13:01:E5:D5:63:6D:39:B6:62:0F:47:65] fingerprint:E4:80:DF:05:83:89:D9:CF:E7:94:CB:38:27:0C:02:A3:20:74:3E:7C not_after:1.6157232e+09 not_before:1.5840576e+09 serial_number:2A03B991467D5A7B9AC587FE4236754 subject:map[C:<nil> CN:hennieyeh.com L:<nil> O:<nil> OU:<nil> ST:<nil> aggregated:/CN=hennieyeh.com]] seen:1.584546695644861e+09 source:map[name:Google 'Rocketeer' log url:ct.googleapis.com/rocketeer/] update_type:X509LogEntry] message_type:certificate_update]}
*/
