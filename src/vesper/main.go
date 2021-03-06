// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"context"
	"time"
	"strings"
	"regexp"
	"github.com/httprouter"
	"github.com/cors"
	"vesper/configuration"
	"vesper/rootcerts"
	"vesper/eks"
	"vesper/sticr"
	"vesper/signcredentials"
	"vesper/replayattack"
	"vesper/publickeys"
	kitlog "github.com/go-kit/kit/log"
)

var (
	glogger											kitlog.Logger
	rootCerts										*rootcerts.RootCerts
	signingCredentials					*signcredentials.SigningCredentials
	eksCredentials							*eks.EksCredentials
	x5u													*sticr.SticrHost
	httpClient									*http.Client
	regexInfo										*regexp.Regexp
	regexAlg										*regexp.Regexp
	regexPpt										*regexp.Regexp
	replayAttackCache						*replayattack.Cache
)

// ErrorBlob -- This is a standard error object
type ErrorBlob struct {
	ReasonCode string `json:"reasonCode"`
	ReasonString string `json:"reasonString"`
}

// Read config file
// Instantiate logging
func init() {
	if (len(os.Args) != 2) {
		log.Fatal("The config file (ABSOLUTE PATH + FILE NAME) must be the only command line arguement")
	}

	// read config
	err := configuration.ConfigurationInstance().GetConfiguration(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Initialize logging
	err = initializeLogging()
	if err != nil {
		log.Fatal(err)
	}

	// create http client object once - to be reused
	httpClient = &http.Client{Timeout: time.Duration(2 * time.Second)}
	
	// initiatlize sks credentials object
	eksCredentials, err = eks.InitObject(configuration.ConfigurationInstance().EksCredentialsFile)
	if err != nil {
		logCritical("type", "eksConfig", "message", fmt.Sprintf("%v.... cannot start Vesper Service .... ", err))
		os.Exit(1)
	}

	// initiatlize sticr object
	x5u, err = sticr.InitObject(configuration.ConfigurationInstance().SticrHostFile)
	if err != nil {
		logCritical("type", "sticrConfig", "message", fmt.Sprintf("%v.... cannot start Vesper Service .... ", err))
		os.Exit(2)
	}	
	
	// After sks credentials object is successfully initialized, initiatlize rootcerts object
	signingCredentials, err = signcredentials.InitObject(glogger, softwareVersion, httpClient, eksCredentials, x5u)
	if err != nil {
		logCritical("type", "signingCredentials", "message", fmt.Sprintf("%v.... cannot start Vesper Service .... ", err))
		os.Exit(3)
	}

	// After sks credentials object is successfully initialized, initiatlize rootcerts object
	rootCerts, err = rootcerts.InitObject(glogger, softwareVersion, httpClient, eksCredentials)
	if err != nil {
		logCritical("type", "rootCerts", "message", fmt.Sprintf("%v.... cannot start Vesper Service .... ", err))
		os.Exit(4)
	}
	
	// instantiate cache to hold stringified claims from identity header in request payload, during verification
	replayAttackCache = replayattack.InitObject()
	
	// Compile the expression once
	regexInfo = regexp.MustCompile(`^info=<..*>$`)
	regexAlg = regexp.MustCompile(`^alg=ES256$`)
	regexPpt = regexp.MustCompile(`^ppt=shaken$`)
}

//
func main() {
	logInfo("type", "start", "message", "Starting vesper .... ")
	stop := make(chan os.Signal, 1)
	signal.Ignore(syscall.SIGPIPE)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	router := httprouter.New()
	router.GET("/v1/version", version)
	router.GET("/stir/v1/stats", getStats)
	router.POST("/stir/v1/signing", signRequest)
	router.POST("/stir/v1/verification", verifyRequest)
	router.POST("/stir/v1/resetstats", resetStats)

	// Start the service.
	// Note: netstats -plnt shows a IPv6 TCP socket listening on localhost:9000
	//       but no IPv4 TCP socket. This is not an issue
	c := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"accept", "Content-Type", "Authorization"},
		AllowCredentials: true,
	})
	handler := c.Handler(router)
	errs := make(chan error)

	// start periodic tickers - each in a separate goroutine
	stopEksCredentialsRefreshTicker := make(chan struct{})
	go func() {
		// start periodic ticker to refresh server jwt to call EKS APIs
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		eksCredentialsRefreshTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().EksCredentialsRefreshInterval)*time.Minute)
		defer eksCredentialsRefreshTicker.Stop()
		for {
			select {
			case <- eksCredentialsRefreshTicker.C:
				// check for eks config changes
				err := eksCredentials.UpdateEksCredentials()
				if err != nil {
					logInfo("type", "refreshEksCredentials", "message", fmt.Sprintf("%v", err))
				}
			case <- stopEksCredentialsRefreshTicker:
				logInfo("type", "timerStop", "message", "stopped eks credentials refresh ticker")
				return
			}
		}
	}()
	stopSticrRefreshTicker := make(chan struct{})
	go func() {
		// start periodic ticker to check on changes to sticr URL
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		sticrRefreshTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().SticrFileCheckInterval)*time.Minute)
		defer sticrRefreshTicker.Stop()
		for {
			select {
			case <- sticrRefreshTicker.C:
				x5u.UpdateSticrHost()
			case <- stopSticrRefreshTicker:
				logInfo("type", "timerStop", "message", "stopped sticr url refresh ticker")
				return
			}
		}
	}()
	

	stopRootCertsRefreshTicker := make(chan struct{})
	go func() {
		// start periodic ticker to pull latest root certs from EKS
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		rootCertsRefreshTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().RootCertsFetchInterval)*time.Second)
		defer rootCertsRefreshTicker.Stop()
		for {
			select {
			case <- rootCertsRefreshTicker.C:
				// fetch root certs from EKS and replace cached ones
				rootCerts.FetchRootCertsFromEks()
			case <- stopRootCertsRefreshTicker:
				logInfo("type", "timerStop", "message", "stopped root certs refresh ticker")
				return
			}
		}
	}()
	stopSigningCredentialsRefreshTicker := make(chan struct{})
	go func() {
		// start periodic ticker to refresh  current signing credentials - x5u and privatekey
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		signingCredentialsRefreshTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().SigningCredentialsFetchInterval)*time.Second)
		defer signingCredentialsRefreshTicker.Stop()
		for {
			select {
			case <- signingCredentialsRefreshTicker.C:
				// fetch current x5u and privatekey for signing. This will replace cached credentials
				signingCredentials.FetchSigningCredentialsFromEks()
			case <- stopSigningCredentialsRefreshTicker:
				logInfo("type", "timerStop", "message", "stopped signing credentials refresh ticker")
				return
			}
		}
	}()
	stopReplayAttackCacheValidationTicker := make(chan struct{})
	go func() {
		t := time.Now().Unix()		// time at startup
		// start periodic ticker to clear stale replay attack cache
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		replayAttackCacheValidationTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().ReplayAttackCacheValidationInterval)*time.Second)
		defer replayAttackCacheValidationTicker.Stop()
		for {
			select {
			case <- replayAttackCacheValidationTicker.C:
				// periodic cleanup of stale replay attack cache
				replayAttackCache.Remove(t)
				t += 1	// increment time by 1 second; no mutex needed here
			case <- stopReplayAttackCacheValidationTicker:
				logInfo("type", "timerStop", "message", "stopped stale replay attack cache ticker")
				return
			}
		}
	}()
	stopPublicKeysCacheFlushTicker := make(chan struct{})
	go func() {
		// start periodic ticker to clear all cached public keys
		// NewTicker returns a new Ticker containing a channel that will send the time with
		// a period specified by the duration argument. It adjusts the intervals or drops
		// ticks to make up for slow receiver.
		// https://golang.org/pkg/time/#NewTicker
		publicKeysCacheFlushTicker := time.NewTicker(time.Duration(configuration.ConfigurationInstance().PublicKeysCacheFlushInterval)*time.Second)
		defer publicKeysCacheFlushTicker.Stop()
		for {
			select {
			case <- publicKeysCacheFlushTicker.C:
				publickeys.FlushCache()
			case <- stopPublicKeysCacheFlushTicker:
				logInfo("type", "timerStop", "message", "stopped public keys cache flush ticker")
				return
			}
		}
	}()
	
	var srv http.Server
	// Start HTTPS server only if cert and key file exist
	if (len(strings.TrimSpace(configuration.ConfigurationInstance().SslCertFile)) > 0) && (len(strings.TrimSpace(configuration.ConfigurationInstance().SslKeyFile)) > 0) {
		go func() {
			httpPort := ":443"
			if len(strings.TrimSpace(configuration.ConfigurationInstance().HttpPort)) > 0 {
				httpPort = ":" + configuration.ConfigurationInstance().HttpPort
			} 
			logInfo("type", "httpsServiceStart", "message", fmt.Sprintf("Staring HTTPS service on port %v ...", httpPort))
			// Note: netstats -plnt shows a IPv6 TCP socket listening on ":443"
			//       but no IPv4 TCP socket. This is not an issue
			srv := &http.Server{Addr: httpPort, Handler: handler}
			if err := srv.ListenAndServeTLS(configuration.ConfigurationInstance().SslCertFile, configuration.ConfigurationInstance().SslKeyFile); err != nil {
				logError("type", "httpServiceFailure", "message", fmt.Sprintf("%v - could not start serving service", err))
				errs <- err
			}
		}()
	} else {
		// Start HTTP server
		go func() {
			httpPort := "80"
			if len(strings.TrimSpace(configuration.ConfigurationInstance().HttpPort)) > 0 {
				httpPort = configuration.ConfigurationInstance().HttpPort
			}
			httpHost := "127.0.0.1" 
			if len(strings.TrimSpace(configuration.ConfigurationInstance().HttpHost)) > 0 {
				httpHost = configuration.ConfigurationInstance().HttpHost
			}
			hostPort := httpHost + ":" + httpPort
			logInfo("type", "httpServiceStart", "message", fmt.Sprintf("starting HTTP service on %v ...", hostPort))
			// Start the service.
			// Note: netstats -plnt shows a IPv6 TCP socket listening on user specified port
			//       but no IPv4 TCP socket. This is not an issue
			srv := &http.Server{Addr: hostPort, Handler: handler}
			if err := srv.ListenAndServe(); err != nil {
				logError("type", "httpServiceFailure", "message", fmt.Sprintf("%v - Could not start serving service", err))
				errs <- err
			}
		 }()
	}

	// This will run forever until channel receives error
	select {
	case err := <-errs:
		logError("type", "httpServiceFailure", "message", fmt.Sprintf("%v - Could not start serving service", err))
		logInfo("type", "shutdown", "message", "shutting down vesper .... ")
	case <-stop:
		logInfo("type", "shutdown", "message", "shutting down vesper .... ")
		// Pass a context with a timeout to tell a blocking function that it
		// should abandon its work after the timeout elapses.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			logError("type", "httpServiceShutdownFailure", "message", fmt.Sprintf("%v - http server shutdown", err))
			logInfo("type", "stop", "message", "vesper stopped but NOT gracefully")
		} else {
			logInfo("type", "stop", "message", "vesper gracefully stopped")
		}
	}
}
