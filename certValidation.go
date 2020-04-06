package main

import (
	"strings"
)

// GetCertValidationType provides a lookup for policy numbers
// see https://www.globalsign.com/en/ssl-information-center/telling-dv-and-ov-certificates-apart
func GetCertValidationType(policiesString string) string {

	entries := strings.Split(policiesString, "\n")
	details := ""

	for _, entry := range entries {
		if strings.HasPrefix(entry, "Policy: ") {
			if details == "" {
				details = lookupValidationCode(entry)
			} else {
				details += ", " + lookupValidationCode(entry)
			}
		}
	}

	return details
}

// taken from https://raw.githubusercontent.com/zmap/constants/master/x509/certificate_policies.csv
func lookupValidationCode(entry string) string {

	// strip start "Policy: "
	entry = entry[8:]

	// strip whitespace
	entry = strings.TrimSpace(entry)

	switch entry {
	default:
		//log.Printf("Unknown validation ID: %q\n", entry)
		return "Unknown"
	case "1.3.6.1.4.1.22177.300.2.1.4.5":
		return "Erklärung zum Zertifizierungsbetrieb der DFN-PKI - Sicherheitsniveau Global - Version 5"
	case "1.3.6.1.4.1.5923.1.4.3.1.1":
		return "InCommon CPS"
	case "2.16.76.1.2.1.91":
		return "SERPRO-RFB-SSL"
	case "1.3.6.1.4.1.53827.1.1.4":
		return "JPRS CA Certificate Policy (CP)"
	case "1.3.6.1.4.1.53827.1.2.4":
		return "JPRS CA Certification Practice Statement (CPS)"
	case "1.2.616.1.113527.2.5.1.9.2.3":
		return "nazwaSSL"
	case "1.3.6.1.4.1.782.1.2.1.8.1":
		return "Network Solutions Certification EV TLS Server Certificates"
	case "1.3.6.1.4.1.782.1.2.1.3.1":
		return "Network Solutions Certification OV TLS Server Certificates"
	case "1.3.6.1.4.1.782.1.2.1.9.1":
		return "Network Solutions Certification DV TLS Server Certificates"
	case "2.23.140.1.2.1":
		return "Network Solutions Certification DV TLS Server Certificates"
	case "2.23.140.1.2.2":
		return "Network Solutions Certification OV TLS Organization Server Certificates"
	case "2.23.140.1.2.3":
		return "Network Solutions Certification OV TLS Individual Server Certificates"
	case "2.23.140.1.1":
		return "Network Solutions Certification EV TLS Server Certificate"
	case "1.3.6.1.4.1.4146.1.10":
		return "AlphaSSL (previously, BelSign) Domain Validation Certificate Policy"
	case "2.16.840.1.114028.10.1.5":
		return "Entrust CA"
	case "1.3.6.1.4.1.311.42.1":
		return "Microsoft IT SSL CA"
	case "1.3.159.1.23.1":
		return "wildcard Domain Validated (DV) policy"
	case "0.4.0.1456.1.1":
		return "ETSI QCP Public + SSCD"
	case "0.4.0.1456.1.2":
		return "ETSI QCP Public"
	case "0.4.0.194112.1.0":
		return "ETSI QCP Natural Person"
	case "0.4.0.194112.1.1":
		return "ETSI QCP Legal Person"
	case "0.4.0.194112.1.2":
		return "ETSI QCP Natural  key in QSCD"
	case "0.4.0.194112.1.3":
		return "ETSI QCP Legal key in QSCD"
	case "0.4.0.194112.1.4":
		return "ETSI QCP Web"
	case "0.4.0.2042.1.1":
		return "Advanced Certificate Policy (Individual or Professional)"
	case "0.4.0.2042.1.2":
		return "ETSI NCP+"
	case "0.4.0.2042.1.4":
		return "ETSI Extended Validation Policy"
	case "0.4.0.2042.1.5":
		return "ETSI EV requiring a secure user device (EVCP+)"
	case "0.4.0.2042.1.6":
		return "ETSI SSL DV"
	case "0.4.0.2042.1.7":
		return "ETSI SSL OV"
	case "1.2.156.112559.1.1.1.1":
		return "GDCA Type I individual"
	case "1.2.156.112559.1.1.1.2":
		return "GDCA Type II individual"
	case "1.2.156.112559.1.1.1.3":
		return "GDCA Type III individual"
	case "1.2.156.112559.1.1.1.4":
		return "GDCA Type IV individual"
	case "1.2.156.112559.1.1.2.1":
		return "GDCA Type III organization"
	case "1.2.156.112559.1.1.2.2":
		return "GDCA  Type IV organization"
	case "1.2.156.112559.1.1.3.1":
		return "GDCA Equipment"
	case "1.2.156.112559.1.1.4.1":
		return "GDCA SSL OV"
	case "1.2.156.112559.1.1.4.2":
		return "GDCA SSL IV"
	case "1.2.156.112559.1.1.4.3":
		return "GDCA SSL DV"
	case "1.2.156.112559.1.1.5.1":
		return "GDCA General CodeSigning "
	case "1.2.156.112559.1.1.6.1":
		return "GDCA SSL EV"
	case "1.2.156.112559.1.1.7.1":
		return "GDCA Code Signing EV"
	case "1.2.156.112570.1.1.3":
		return "Sheca EV"
	case "1.2.392.200091.100.721.1":
		return "SECOM Trust Systems"
	case "1.2.40.0.17.1.22":
		return "A-Trust-nQual-03 EV"
	case "1.3.159.1.17.1":
		return "Actalis Authentication Root CA"
	case "1.3.6.1.4.1.11129.2.5.1":
		return "Google Internet Authority G2"
	case "1.3.6.1.4.1.11129.2.5.3":
		return "Google Trust Services"
	case "1.3.6.1.4.1.13177.10.1.3.10":
		return "Firmaprofesional"
	case "1.3.6.1.4.1.14370.1.6":
		return "GeoTrust EV CPS 2.6"
	case "1.3.6.1.4.1.14777.1.1.3":
		return "Izenpe Electronic Office"
	case "1.3.6.1.4.1.14777.1.2.1":
		return "Izenpe OV"
	case "1.3.6.1.4.1.14777.1.2.4":
		return "Izenpe DV"
	case "1.3.6.1.4.1.14777.6.1.1":
		return "Izenpe EV"
	case "1.3.6.1.4.1.14777.6.1.2":
		return "Izenpe Electronic Office EV"
	case "1.3.6.1.4.1.17326.10.14.2.1.2":
		return "Camerfirma S.A. Chambers of Commerce EV"
	case "1.3.6.1.4.1.17326.10.14.2.2.2":
		return "Camerfirma S.A. Chambers of Commerce EV"
	case "1.3.6.1.4.1.17326.10.8.12.1.2":
		return "Camerfirma S.A. Global Chambersign Root"
	case "1.3.6.1.4.1.17326.10.8.12.2.2":
		return "Camerfirma S.A. Global Chambersign Root"
	case "1.3.6.1.4.1.18332.55.1.1":
		return "ANF Autoridad de Certificacion"
	case "1.3.6.1.4.1.18332.55.1.1.1.22":
		return "ANF AC Secure Server SSL DV"
	case "1.3.6.1.4.1.18332.55.1.1.2.22":
		return "ANF AC Secure Server SSL EV"
	case "1.3.6.1.4.1.18332.55.1.1.3.22":
		return "ANF AC Medium Level Electronic Headquarters"
	case "1.3.6.1.4.1.18332.55.1.1.4.22":
		return "ANF AC High Level Electronic Headquarters"
	case "1.3.6.1.4.1.18332.55.1.1.5.22":
		return "ANF AC Medium Level Electronic Headquarters EV"
	case "1.3.6.1.4.1.18332.55.1.1.6.22":
		return "ANF AC High Level Electronic Headquarters EV"
	case "1.3.6.1.4.1.18332.55.1.1.7.22":
		return "ANF AC Secure Server SSL OV"
	case "1.3.6.1.4.1.22234.2.5.2.3.1":
		return "KEYNECTIS Extended Validation CA"
	case "1.3.6.1.4.1.23223.1.1.1":
		return "StartCom EV Current"
	case "1.3.6.1.4.1.23223.2":
		return "StartCom CPS no.4"
	case "1.3.6.1.4.1.26513.1.0.2.3":
		return "HARICA CPS v2.3"
	case "1.3.6.1.4.1.26513.1.0.2.4":
		return "HARICA CPS v2.4"
	case "1.3.6.1.4.1.26513.1.0.2.5":
		return "HARICA CPS v2.5"
	case "1.3.6.1.4.1.26513.1.0.2.6":
		return "HARICA CPS v2.6"
	case "1.3.6.1.4.1.26513.1.0.2.7":
		return "HARICA CPS v2.7"
	case "1.3.6.1.4.1.26513.1.0.3.0":
		return "HARICA CPS v3.0"
	case "1.3.6.1.4.1.26513.1.0.3.1":
		return "HARICA CPS v3.1"
	case "1.3.6.1.4.1.26513.1.0.3.2":
		return "HARICA CPS v3.2"
	case "1.3.6.1.4.1.26513.1.0.3.3":
		return "HARICA CPS v3.3"
	case "1.3.6.1.4.1.26513.1.0.3.4":
		return "HARICA CPS v3.4"
	case "1.3.6.1.4.1.26513.1.0.3.5":
		return "HARICA CPS v3.5"
	case "1.3.6.1.4.1.30360.3.3.3.3.4.4.3.0":
		return "Trustwave"
	case "1.3.6.1.4.1.34697.1.1":
		return "Trend"
	case "1.3.6.1.4.1.34697.2":
		return "AffirmTrust"
	case "1.3.6.1.4.1.34697.2.1":
		return "AffirmTrust Commercial Root EV"
	case "1.3.6.1.4.1.34697.2.2":
		return "AffirmTrust Networking Root EV"
	case "1.3.6.1.4.1.34697.2.3":
		return "AffirmTrust Premium Root EV"
	case "1.3.6.1.4.1.34697.2.4":
		return "AffirmTrust Premium ECC Root EV"
	case "1.3.6.1.4.1.36305.2":
		return "Wosign EV"
	case "1.3.6.1.4.1.4146.1.1":
		return "Globalsign EV"
	case "1.3.6.1.4.1.4146.1.10.10":
		return "Globalsign DV"
	case "1.3.6.1.4.1.4146.1.20":
		return "Globalsign OV"
	case "1.3.6.1.4.1.44947.1.1.1":
		return "Let's Encrypt"
	case "1.3.6.1.4.1.4788.2.200.1":
		return "D-Trust OV"
	case "1.3.6.1.4.1.4788.2.202.1":
		return "D-Trust EV"
	case "1.3.6.1.4.1.5237.1.1.3":
		return "Trustis"
	case "1.3.6.1.4.1.6334.1.100.1":
		return "Cybertrust EV"
	case "1.3.6.1.4.1.6449.1.2.1.1.1":
		return "Comodo SMIME Class 1"
	case "1.3.6.1.4.1.6449.1.2.1.3.1":
		return "Comodo TLS OV (Old)"
	case "1.3.6.1.4.1.6449.1.2.1.3.2":
		return "Comodo Code Signing OV"
	case "1.3.6.1.4.1.6449.1.2.1.3.4":
		return "Comodo Code Signing OV"
	case "1.3.6.1.4.1.6449.1.2.1.3.5":
		return "Comodo SMIME Class 3"
	case "1.3.6.1.4.1.6449.1.2.1.5.1":
		return "Comodo TLS EV"
	case "1.3.6.1.4.1.6449.1.2.1.6.1":
		return "Comodo Code Signing EV"
	case "1.3.6.1.4.1.6449.1.2.2.10":
		return "Comodo - eNom DV"
	case "1.3.6.1.4.1.6449.1.2.2.11":
		return "Comodo - GlobalTrust"
	case "1.3.6.1.4.1.6449.1.2.2.12":
		return "Comodo - ARX"
	case "1.3.6.1.4.1.6449.1.2.2.14":
		return "Comodo - Admiral Systems"
	case "1.3.6.1.4.1.6449.1.2.2.15":
		return "Comodo - WoTrust"
	case "1.3.6.1.4.1.6449.1.2.2.16":
		return "Comodo - RBC SOFT"
	case "1.3.6.1.4.1.6449.1.2.2.17":
		return "Comodo - RegisterFly"
	case "1.3.6.1.4.1.6449.1.2.2.18":
		return "Comodo - Central Security Patrol"
	case "1.3.6.1.4.1.6449.1.2.2.19":
		return "Comodo - eBiz Networks"
	case "1.3.6.1.4.1.6449.1.2.2.20":
		return "Comodo - RegistryPro"
	case "1.3.6.1.4.1.6449.1.2.2.21":
		return "Comodo - OptimumSSL"
	case "1.3.6.1.4.1.6449.1.2.2.22":
		return "Comodo - WoSign"
	case "1.3.6.1.4.1.6449.1.2.2.23.1":
		return "Comodo - State of Oregon"
	case "1.3.6.1.4.1.6449.1.2.2.24":
		return "Comodo - Register.com"
	case "1.3.6.1.4.1.6449.1.2.2.25":
		return "Comodo - The Code Project"
	case "1.3.6.1.4.1.6449.1.2.2.26":
		return "Comodo - Gandi"
	case "1.3.6.1.4.1.6449.1.2.2.27":
		return "Comodo - GlobeSSL"
	case "1.3.6.1.4.1.6449.1.2.2.28":
		return "Comodo - DreamHost"
	case "1.3.6.1.4.1.6449.1.2.2.29":
		return "Comodo - TERENA"
	case "1.3.6.1.4.1.6449.1.2.2.30":
		return "Comodo - SIGNGATE"
	case "1.3.6.1.4.1.6449.1.2.2.31":
		return "Comodo - GlobalSSL"
	case "1.3.6.1.4.1.6449.1.2.2.35":
		return "Comodo - IceWarp"
	case "1.3.6.1.4.1.6449.1.2.2.36.1":
		return "Comodo - University of Texas San Antonio"
	case "1.3.6.1.4.1.6449.1.2.2.36.2":
		return "Comodo - University of Texas Austin"
	case "1.3.6.1.4.1.6449.1.2.2.36.3":
		return "Comodo - University of Texas Dallas"
	case "1.3.6.1.4.1.6449.1.2.2.36.4":
		return "Comodo - University of Texas Pan American"
	case "1.3.6.1.4.1.6449.1.2.2.36.5":
		return "Comodo - University of Texas Houston"
	case "1.3.6.1.4.1.6449.1.2.2.36.6":
		return "Comodo - University of Texas Arlington"
	case "1.3.6.1.4.1.6449.1.2.2.37":
		return "Comodo - Dotname Korea"
	case "1.3.6.1.4.1.6449.1.2.2.38":
		return "Comodo - TrustSign"
	case "1.3.6.1.4.1.6449.1.2.2.39":
		return "Comodo - Formidable"
	case "1.3.6.1.4.1.6449.1.2.2.40":
		return "Comodo - SSL Blindado"
	case "1.3.6.1.4.1.6449.1.2.2.41":
		return "Comodo - Dreamscape Networks"
	case "1.3.6.1.4.1.6449.1.2.2.42":
		return "Comodo - K Software"
	case "1.3.6.1.4.1.6449.1.2.2.43":
		return "Comodo - McAfee"
	case "1.3.6.1.4.1.6449.1.2.2.44":
		return "Comodo - FBS"
	case "1.3.6.1.4.1.6449.1.2.2.45":
		return "Comodo - ReliaSite"
	case "1.3.6.1.4.1.6449.1.2.2.46":
		return "Comodo - Flextronics"
	case "1.3.6.1.4.1.6449.1.2.2.47":
		return "Comodo - CertAssure"
	case "1.3.6.1.4.1.6449.1.2.2.49":
		return "Comodo - TrustAsia"
	case "1.3.6.1.4.1.6449.1.2.2.5":
		return "Comodo - eNom OV"
	case "1.3.6.1.4.1.6449.1.2.2.50":
		return "Comodo - SecureCore"
	case "1.3.6.1.4.1.6449.1.2.2.51":
		return "Comodo - Western Digital"
	case "1.3.6.1.4.1.6449.1.2.2.52":
		return "Comodo - cPanel"
	case "1.3.6.1.4.1.6449.1.2.2.53":
		return "Comodo - BlackCert"
	case "1.3.6.1.4.1.6449.1.2.2.54":
		return "Comodo - KeyNet Systems"
	case "1.3.6.1.4.1.6449.1.2.2.55":
		return "Comodo - InterContinental Hotels"
	case "1.3.6.1.4.1.6449.1.2.2.56":
		return "Comodo - UPS"
	case "1.3.6.1.4.1.6449.1.2.2.57":
		return "Comodo - Saint Barnabas Corp"
	case "1.3.6.1.4.1.6449.1.2.2.6":
		return "Comodo - DigiCert"
	case "1.3.6.1.4.1.6449.1.2.2.7":
		return "Comodo TLS DV"
	case "1.3.6.1.4.1.6449.1.2.2.8":
		return "Comodo - CSC"
	case "1.3.6.1.4.1.6449.1.2.2.9":
		return "Comodo - Digi-Sign"
	case "1.3.6.1.4.1.6449.1.2.3.1":
		return "Comodo Usertrust"
	case "1.3.6.1.4.1.7879.13.24.1":
		return "T-Systems International GmbH EV"
	case "1.3.6.1.4.1.8024.0.2.100.1.1":
		return "QuoVadis OV"
	case "1.3.6.1.4.1.8024.0.2.100.1.2":
		return "QuoVadis EV"
	case "2.16.156.339.1.1.1.2.1":
		return "Hong Kong-Guangdong mutual recognition individual certificates"
	case "2.16.156.339.1.1.2.2.1":
		return "Hong Kong-Guangdong mutual recognition organization certificates"
	case "2.16.528.1.1001.1.1.1.12.6.1.1.1":
		return "DigiNotar CPS 3.5"
	case "2.16.528.1.1003.1.1.1":
		return "Logius PKI voor deoverheid"
	case "2.16.528.1.1003.1.2.5.6":
		return "Logius OV"
	case "2.16.528.1.1003.1.2.7":
		return "Logius EV"
	case "2.16.578.1.26.1.3.3":
		return "Buypass Class 3 CA SSL EV"
	case "2.16.756.1.83.21.0":
		return "Swisscom Root Extended Validation (EV) CA 2"
	case "2.16.756.1.89.1.2.1.1":
		return "Swisscom EV"
	case "2.16.792.1.2.1.1.5.7.1.9":
		return "Kamu Sertifikasyon Merkezi SSL"
	case "2.16.792.3.0.3.1.1.2":
		return "TurkTrust OV"
	case "2.16.792.3.0.3.1.1.5":
		return "TurkTrust EV"
	case "2.16.792.3.0.4.1.1.1":
		return "Qualified Electronic Certificate Policy"
	case "2.16.792.3.0.4.1.1.2":
		return "Standard SSL Certificate Policy"
	case "2.16.792.3.0.4.1.1.3":
		return "Premium SSL Certificate Policy"
	case "2.16.792.3.0.4.1.1.4":
		return "E-Tugra EV SSL Certificate Policy"
	case "2.16.840.1.101.3.2.1.1. 5":
		return "Identrust Public Sector"
	case "2.16.840.1.113733.1.7.23.1":
		return "Symantec Class 1"
	case "2.16.840.1.113733.1.7.23.2":
		return "Symantec Class 2"
	case "2.16.840.1.113733.1.7.23.3":
		return "Symantec Class 3"
	case "2.16.840.1.113733.1.7.23.3.2":
		return "Symantec Class 3 (Private)"
	case "2.16.840.1.113733.1.7.23.6":
		return "Verisign EV CPS v3.8"
	case "2.16.840.1.113733.1.7.48.1":
		return "Thawte EV CPS v. 3.3"
	case "2.16.840.1.113733.1.7.54":
		return "Symantec"
	case "2.16.840.1.113733.1.8.54.1":
		return "Symantec <2048-bit"
	case "2.16.840.1.113839.0.6.3":
		return "Identrust Commercial"
	case "2.16.840.1.114028.10.1.2":
		return "Entrust Extended Validation (EV)"
	case "2.16.840.1.114171.500.9":
		return "WellsFargo WellsSecure"
	case "2.16.840.1.114404.1.1.2.4.1":
		return "SecureTrust EV CPS v1.1.1"
	case "2.16.840.1.114412.1.1":
		return "Digicert OV"
	case "2.16.840.1.114412.1.2":
		return "Digicert DV"
	case "2.16.840.1.114412.1.3.0.2":
		return "Digicert EV"
	case "2.16.840.1.114412.2.1":
		return "Digicert EV"
	case "2.16.840.1.114413.1.7.23.1":
		return "GoDaddy DV"
	case "2.16.840.1.114413.1.7.23.2":
		return "GoDaddy OV"
	case "2.16.840.1.114413.1.7.23.3":
		return "GoDaddy EV"
	case "2.16.840.1.114414.1.7.23.1":
		return "Starfield DV"
	case "2.16.840.1.114414.1.7.23.2":
		return "Starfield OV"
	case "2.16.840.1.114414.1.7.23.3":
		return "Starfield EV"
	case "2.23.140":
		return "CA/B Forum"
	case "2.23.140.1.2":
		return "CA/B Forum Baseline Requirements"
	case "2.23.140.1.3":
		return "CA/B Forum CA/B Forum Extended Validation Code Signing"
	case "2.23.140.1.31":
		return "CA/B Forum .onion EV"
	}
}
