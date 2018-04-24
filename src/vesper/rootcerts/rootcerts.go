package rootcerts

import (
	"fmt"
	"time"
	"sync"
	"strings"
	"io/ioutil"
	"encoding/json"
	"crypto/x509"
	"net/http"
	"vesper/configuration"
	"vesper/sks"
	"github.com/comcast/irislogger"
)

// globals
var (
	info										*irislogger.Logger
	softwareVersion					string
	httpClient							*http.Client
	sksCredentials					*sks.SksCredentials
)


// function to log in specific format
func logInfo(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().Host + ", Version=" + softwareVersion + ", Code=Info, " + format, args ...)
}

// function to log in specific format
func logError(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + configuration.ConfigurationInstance().Host + ", Version=" + softwareVersion + ", Code=ErrorInfo, " + format, args ...)
}

// RootCerts - structure that holds all root certs
type RootCerts struct {
	sync.RWMutex	// A field declared with a type but no explicit field name is an
					// anonymous field, also called an embedded field or an embedding of
					// the type in the structembedded. see http://golang.org/ref/spec#Struct_types
	certs *x509.CertPool
}
  
// Initialize object
func InitObject(i *irislogger.Logger, v string, h *http.Client, s *sks.SksCredentials) (*RootCerts, error) {
	info = i
	softwareVersion = v
	httpClient = h
	sksCredentials = s
	rc := new(RootCerts)
	var err error
	rc.certs, err = getRootCertsFromSks()
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// fetch rootcerts from sks
func (rc *RootCerts) FetchRootCertsFromSks() error {
	c, err := getRootCertsFromSks()
	rc.Lock()
	defer rc.Unlock()
	if err == nil {
		rc.certs = c
	}
	return err
}


// using Lock() ensures all RLocks() are blocked when alerts are being updated
func (rc *RootCerts) Root() *x509.CertPool {
	rc.RLock()
	defer rc.RUnlock()
	return rc.certs
}

func getRootCertsFromSks() (*x509.CertPool, error) {
	certs := x509.NewCertPool()
	// Request root certs from SKS
	start := time.Now()
	u, t := sksCredentials.GetSksCredentials()
	url := u + "/whitelist"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%v - http.NewRequest failed", err)
	}
	req.Header.Set("X-Vault-Token", t)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%v - GET %v failed", err, url)
	}
	defer resp.Body.Close()
	logInfo("Type=vesperRequestResponseTime, Module=getRootCertsFromSks, Message=Response time : %v", time.Since(start))
	var s map[string]interface{}
	rb, err := ioutil.ReadAll(resp.Body)
	if err == nil {
		if len(rb) > 0 {
			c := resp.Header.Get("Content-Type")
			if strings.Contains(c, "application/json") {
				err = json.Unmarshal(rb, &s)
				if err != nil {
					return nil, fmt.Errorf("GET %v response status - %v; unable to parse JSON object in response body (from SKS) - %v", url, resp.StatusCode, err)
				}
			}
		} else {
			return nil, fmt.Errorf("GET %v response status - %v; nothing read from response body (from SKS)", url, resp.StatusCode)
		}
	} else {
		return nil, fmt.Errorf("GET %v response status - %v; %v - response body (from SKS)", url, resp.StatusCode, err)
	}
	switch resp.StatusCode {
	case 200:
		// s contains
		if data, ok := s["data"]; ok {
			switch r1 := data.(type) {
			case map[string]interface{}:
				if r2, ok := r1["rootcerts"]; ok {
					switch r2.(type) {
					case string:
						// Append our cert to the system pool
						if ok := certs.AppendCertsFromPEM([]byte(r1["rootcerts"].(string))); !ok {
							return nil, fmt.Errorf("No certs appended")
						}
						return certs, nil
					default:
						return nil, fmt.Errorf("GET %v response status - %v; \"rootcerts\" field MUST be a string in %+v returned by SKS", url, resp.Status, s)
					}
				} else {
					return nil, fmt.Errorf("GET %v response status - %v; \"rootcerts\" field missing in in %+v returned by SKS", url, resp.Status, s)	
				}
			default:
				return nil, fmt.Errorf("GET %v response status - %v; \"data\" field MUST be a map in %+v returned by SKS", url, resp.Status, s)
			}
		}
		return nil, fmt.Errorf("GET %v response status - %v; \"data\" field missing in in %+v returned by SKS", url, resp.Status, s)
	}
	return nil, fmt.Errorf("GET %v response status - %v; response from SKS - %+v", url, resp.StatusCode, s)
}