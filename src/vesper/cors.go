package main

import (
	"github.com/valyala/fasthttp"
)

var (
	corsAllowHeaders     = "accept, Content-Type, Authorization"
	corsAllowMethods     = "GET,POST"
	corsAllowCredentials = "true"
	corsAllowOrigin      = "*"
)

// adds cors headers to response
func cors(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", corsAllowCredentials)
		ctx.Response.Header.Set("Access-Control-Allow-Headers", corsAllowHeaders)
		ctx.Response.Header.Set("Access-Control-Allow-Methods", corsAllowMethods)
		ctx.Response.Header.Set("Access-Control-Allow-Origin", corsAllowOrigin)

		// call the next reqyest in chain
		next(ctx)

	})
}
