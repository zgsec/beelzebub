// Command fpsink is a plaintext-HTTP capture sink for building the AI-client
// fingerprint corpus. It records, per request, the wire-order header names
// (via the production TeeConn + ParseHeaderOrder), the full header values, and
// our canonical JA4H — then answers with a benign JSON body so SDKs don't hard
// fail before their request is sent. Drive real AI SDKs at it and read the JSON
// records off stdout.
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"

	"github.com/mariocandela/beelzebub/v3/tracer"
)

func main() {
	addr := "127.0.0.1:8999"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	enc := json.NewEncoder(os.Stdout)

	srv := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, tracer.TeeConnKey, c)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var wireOrder []string
			if tc, ok := r.Context().Value(tracer.TeeConnKey).(*tracer.TeeConn); ok {
				wireOrder = tracer.ParseHeaderOrder(tc.RawBytes())
			}
			headers := map[string]string{}
			for k, v := range r.Header {
				if len(v) > 0 {
					headers[k] = v[0]
				}
			}
			if r.Host != "" {
				headers["Host"] = r.Host
			}
			_ = enc.Encode(map[string]any{
				"ja4h":         tracer.ComputeJA4H(r, wireOrder),
				"method":       r.Method,
				"path":         r.URL.Path,
				"proto":        r.Proto,
				"header_order": wireOrder,
				"headers":      headers,
				"ua":           r.UserAgent(),
			})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Connection", "close") // fresh connection per request
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object":"list","data":[],"id":"x","content":[{"type":"text","text":"x"}]}`))
		}),
	}
	_ = srv.Serve(tracer.NewTeeListener(ln, 65536, tracer.HTTPStopFunc))
}
