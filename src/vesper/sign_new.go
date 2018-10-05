// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/satori/go.uuid"
	"github.com/valyala/fasthttp"
)

type validationResult struct {
	om  map[string]interface{}
	ec  string
	err error
}

type signingResult struct {
	canonicalString string
	sign            string
	err             error
}

func fSignRequest(ctx *fasthttp.RequestCtx) {
	start := time.Now()
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Content-Type", "application/json")
	clientIP := ctx.RemoteAddr().String()
	traceID := string(ctx.Request.Header.Peek("Trace-Id"))
	if traceID == "" {
		traceID = "VESPER-" + uuid.NewV1().String()
	}
	ctx.Response.Header.Set("Trace-Id", traceID)

	// verify no query is present
	// verify the request body is correct
	var r map[string]interface{}
	err := json.Unmarshal(ctx.PostBody(), &r)
	switch {
	case err == io.EOF:
		// empty request body
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4001, ReasonString=empty request body", traceID, clientIP)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)

		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: "VESPER-4001", ReasonString: "empty request body"}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	case err != nil:
		logError("Type=vesperInvalidJson, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-4002, ReasonString=received invalid json", traceID, clientIP)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: "VESPER-4002", ReasonString: "Unable to parse request body"}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	default:
		// err == nil. continue
	}

	// do validation on a channel
	vc := make(chan validationResult)
	go func(r map[string]interface{}, traceID, clientIP string, vc chan validationResult) {
		orderedMap, _, _, _, _, errCode, err := validatePayload(r, traceID, clientIP)
		vc <- validationResult{orderedMap, errCode, err}
	}(r, traceID, clientIP, vc)

	result := <-vc
	if result.err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: result.ec, ReasonString: result.err.Error()}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	}

	logInfo("Type=vespersignRequest, TraceID=%v, Module=signRequest, Message=%+v", traceID, r)

	x, p := signingCredentials.Signing()
	// at this point, the input has been validated
	hdr := ShakenHdr{Alg: "ES256", Ppt: "shaken", Typ: "passport", X5u: x}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5050, ReasonString=error in converting header to byte array : %v", traceID, clientIP, err)
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: "VESPER-5050", ReasonString: "error in converting header to byte array"}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	}
	claimsBytes, _ := json.Marshal(result.om)
	if err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5051, ReasonString=error in converting claims to byte array : %v", traceID, clientIP, err)

		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: "VESPER-5051", ReasonString: "error in converting claims to byte array"}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	}

	sc := make(chan signingResult)
	go func(hdrBytes, claimsBytes, sp []byte, sc chan signingResult) {
		canonicalString, sig, err := createSignature(hdrBytes, claimsBytes, []byte(p))
		sc <- signingResult{canonicalString, sig, err}

	}(hdrBytes, claimsBytes, []byte(p), sc)

	signRes := <-sc

	if signRes.err != nil {
		logError("Type=vesperRequestPayload, TraceID=%v, ClientIP=%v, Module=signRequest, ReasonCode=VESPER-5052, ReasonString=error in signing request for request payload (%+v) : %v", traceID, clientIP, r, err)

		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		jsonErr := SResponse{SigningResponse: ErrorBlob{ReasonCode: "VESPER-5052", ReasonString: "error in signing request"}}
		json.NewEncoder(ctx).Encode(jsonErr)
		return
	}

	resp := make(map[string]interface{})
	resp["signingResponse"] = make(map[string]interface{})
	resp["signingResponse"].(map[string]interface{})["identity"] = signRes.canonicalString + "." + signRes.sign + ";info=<" + x + ">;alg=ES256"
	ctx.SetStatusCode(fasthttp.StatusOK)
	json.NewEncoder(ctx).Encode(resp)
	logInfo("Type=vesperRequestResponseTime, TraceID=%v,  Message=time spent in signRequest() : %v", traceID, time.Since(start))
}
