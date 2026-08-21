package qlog

import (
	"context"

	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/qlog"
	"github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/internal/quicgo/qlogwriter"
)

const EventSchema = "urn:ietf:params:qlog:events:http3-12"

func DefaultConnectionTracer(ctx context.Context, isClient bool, connID quic.ConnectionID) qlogwriter.Trace {
	return qlog.DefaultConnectionTracerWithSchemas(ctx, isClient, connID, []string{qlog.EventSchema, EventSchema})
}
