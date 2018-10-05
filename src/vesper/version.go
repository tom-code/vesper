// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"encoding/json"
	"net/http"

	"github.com/httprouter"
	"github.com/valyala/fasthttp"
)

const softwareVersion = `2.4`

// VersionQueryResponse -- struct that holds software version
type VersionQueryResponse struct {
	Version string
}

func version(response http.ResponseWriter, request *http.Request, _ httprouter.Params) {

	var jsonResp VersionQueryResponse
	jsonResp.Version = "Vesper Server " + softwareVersion
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	json.NewEncoder(response).Encode(jsonResp)
}

func fversion(ctx *fasthttp.RequestCtx) {

	var jsonResp VersionQueryResponse
	jsonResp.Version = "Vesper Server " + softwareVersion

	ctx.Response.Header.Set("Content-Type", "application/json")
	json.NewEncoder(ctx).Encode(jsonResp)
	ctx.Response.SetStatusCode(http.StatusOK)

}
