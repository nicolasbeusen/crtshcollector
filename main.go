package main

import (
	"bufio"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
)

type Domain struct {
	Domain string `json:"domain"`
	CertID string `json:"cert_id"`
}

func loadCertificateId(certDataFile string, domain string, certId *string) {

	*certId = "0"

	file, err := ioutil.ReadFile(certDataFile)
	if err != nil {
		fmt.Println("Error reading file")
		return
	}

	var domains []Domain
	err = json.Unmarshal(file, &domains)
	if err != nil {
		fmt.Println("Error parsing file")
		return
	}

	for _, d := range domains {
		if d.Domain == domain {
			*certId = d.CertID
			break
		}
	}
	return
}

func saveCertificateId(certDataFile string, domain string, certId string) {

	var domainFound bool = false
	var domains []Domain
	//read file in structure
	file, err := ioutil.ReadFile(certDataFile)
	if err != nil {

		domains = append(domains, Domain{Domain: domain, CertID: certId})

		//If file doesn't exist, create it
		newData, err := json.MarshalIndent(domains, "", "    ")
		if err != nil {
			fmt.Println(err)
			return
		}

		err = ioutil.WriteFile(certDataFile, newData, 0644)
		if err != nil {
			fmt.Println(err)
			return
		}

		return

	}

	err = json.Unmarshal(file, &domains)
	if err != nil {
		fmt.Println("Error parsing file")
		return
	}

	//Find domain & Update cert in struct
	for idx, d := range domains {
		if d.Domain == domain {
			domains[idx].CertID = certId
			domainFound = true
			break
		}
	}

	// If domain not found, add it to the file
	if !domainFound {
		domains = append(domains, Domain{Domain: domain, CertID: certId})
	}

	newData, err := json.MarshalIndent(domains, "", "    ")
	if err != nil {
		fmt.Println(err)
		return
	}

	err = ioutil.WriteFile(certDataFile, newData, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var domain string
	var lastCertificateid string

	var certDataFile string
	flag.StringVar(&certDataFile, "certfile", "", "Cert Data file")
	flag.Parse()

	// read the host and port from pipeline
	for scanner.Scan() {
		domain = scanner.Text()
		//fmt.Println("Looking for : ", domain)

		loadCertificateId(certDataFile, domain, &lastCertificateid)
		//fmt.Println("Cert Found : ", lastCertificateid)

		// Connect to the database
		db, err := sql.Open("postgres", "host=crt.sh port=5432 user=guest password='' dbname=certwatch")
		if err != nil {
			fmt.Println("Error connecting to database:", err)
			return
		}
		defer db.Close()
		var offset int = 0
		var count int = 100
		var certCount int = 0

		for {
			// Execute the query
			sqlRequest := `SELECT min(sub.CERTIFICATE_ID) ID,
									array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES,
									pem_cert(sub.CERTIFICATE)
							FROM (SELECT *
									FROM certificate_and_identities cai
									WHERE plainto_tsquery('certwatch', '%s') @@ identities(cai.CERTIFICATE)
									AND cai.certificate_id > %s
									LIMIT 1000 OFFSET %d
							) sub
							GROUP BY sub.CERTIFICATE, sub.CERTIFICATE_ID 
						ORDER BY sub.CERTIFICATE_ID ASC NULLS LAST`

			//fmt.Println(fmt.Sprintf(sqlRequest, domain, lastCertificateid, offset))
			//return
			rows, err := db.Query(fmt.Sprintf(sqlRequest, domain, lastCertificateid, offset))

			if err != nil {
				fmt.Println("Error executing query:", err)
				return
			}
			defer rows.Close()

			certCount = 0
			// Print the results
			for rows.Next() {
				certCount++
				var certificate_id int
				var certificate string
				var name_value string
				if err := rows.Scan(&certificate_id, &name_value, &certificate); err != nil {
					return
				}

				for block, rest := pem.Decode([]byte(certificate)); block != nil; block, rest = pem.Decode(rest) {
					switch block.Type {
					case "CERTIFICATE":
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							panic(err)
						}

						//fmt.Println("Certificate id : ", certificate_id)

						if strings.Contains(cert.Subject.CommonName, domain) && !strings.Contains(cert.Subject.CommonName, "*") {
							fmt.Println(cert.Subject.CommonName)
						}

						lastCertificateid = strconv.Itoa(certificate_id)
						dnsNames := cert.DNSNames
						for _, dnsName := range dnsNames {
							if strings.Contains(dnsName, domain) && !strings.Contains(dnsName, "*") {
								fmt.Printf("%s\n", dnsName)
							}
						}
					}
				}
			}

			//fmt.Printf("Offset : %d, count : %d, certCount : %d\n", offset, count, certCount)
			offset += count
			if certCount == 0 {
				//Save last certificate if to config file
				break
			}

			//time.Sleep(5 * time.Second)
		}

		//Write last cert to file
		saveCertificateId(certDataFile, domain, lastCertificateid)

	}
}
