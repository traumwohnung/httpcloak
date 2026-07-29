package transport

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	http "github.com/sardanioss/http"

	utls "github.com/sardanioss/utls"

	"github.com/sardanioss/httpcloak/protocol"
)

// Streaming variants of DoOnTLSConn / DoOnH2Conn.
//
// The buffered variants read the entire response body before returning, which
// makes them unusable for a forwarding proxy: server-sent events, long-poll,
// and chunked progress responses are only delivered once the origin ends the
// stream, and large downloads are held in memory in full. These variants hand
// back a live body reader instead.
//
// Two differences from the buffered path matter to callers:
//
//   - The request timeout bounds time-to-response-headers only. Once headers
//     arrive the deadline is defused, so a stream may stay open indefinitely.
//     A caller that wants a total cap must impose it on its own context.
//   - The caller owns the body: the underlying connection is only reusable
//     after Body.Close(), and for HTTP/1.1 the connection must not carry
//     another request until then.

// DoStreamOnH2Conn is DoOnH2Conn without body buffering.
func (t *Transport) DoStreamOnH2Conn(ctx context.Context, req *Request, h2c *H2ClientConn) (*Response, error) {
	if h2c == nil || h2c.h2Conn == nil {
		return nil, fmt.Errorf("transport: DoStreamOnH2Conn called with nil H2ClientConn")
	}
	return t.doStreamOnRoundTripper(ctx, req, "h2", func(httpReq *http.Request) (*http.Response, error) {
		return h2c.h2Conn.RoundTrip(httpReq)
	})
}

// DoStreamOnTLSConn is DoOnTLSConn without body buffering.
//
// The caller must serialize requests on the connection and must keep that
// serialization in force until the returned body is closed — HTTP/1.1 has no
// multiplexing, so a second request written while this body is still draining
// corrupts the framing of both.
func (t *Transport) DoStreamOnTLSConn(ctx context.Context, req *Request, tlsConn *utls.UConn) (*Response, error) {
	if t.h1Transport == nil {
		return nil, fmt.Errorf("transport: HTTP/1.1 subsystem not initialised")
	}
	if tlsConn == nil {
		return nil, fmt.Errorf("transport: DoStreamOnTLSConn called with nil TLS conn")
	}
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	return t.doStreamOnRoundTripper(ctx, req, "h1", func(httpReq *http.Request) (*http.Response, error) {
		return t.h1Transport.RoundTripOnConn(httpReq, tlsConn, host, port)
	})
}

// doStreamOnRoundTripper is the streaming twin of doOnRoundTripper. It shares
// request construction (see prepareOwnedConnRequest — header order and preset
// application must not drift between the two paths, or the two would produce
// different fingerprints) and diverges only in how the response is handled.
func (t *Transport) doStreamOnRoundTripper(
	ctx context.Context,
	req *Request,
	proto string,
	roundTripper func(*http.Request) (*http.Response, error),
) (*Response, error) {
	startTime := time.Now()
	timing := &protocol.Timing{}

	host, port, err := splitHostPortForProto(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", proto, err)
	}

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}

	// Cancellation is tied to the response body, not to this function
	// returning: the body is still being read from the wire after we return.
	// The timeout covers only the wait for response headers — a streaming
	// response that stays open for an hour is a success, not a timeout.
	ctx, cancel := context.WithCancel(ctx)
	headerTimer := time.AfterFunc(timeout, cancel)

	httpReq, err := t.prepareOwnedConnRequest(ctx, req, proto)
	if err != nil {
		headerTimer.Stop()
		cancel()
		return nil, NewRequestError("create_request", host, port, proto, err)
	}

	reqStart := time.Now()
	resp, err := roundTripper(httpReq)
	if err != nil {
		headerTimer.Stop()
		cancel()
		return nil, WrapError("roundtrip", host, port, proto, err)
	}
	// Headers are in. From here the stream sets its own pace.
	headerTimer.Stop()

	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	// Decompress on the fly. Once decoded, the upstream Content-Length no
	// longer describes what the caller reads, so the length becomes unknown.
	contentEncoding := resp.Header.Get("Content-Encoding")
	reader, decompressor := setupStreamDecompressor(resp.Body, contentEncoding)
	contentLength := resp.ContentLength
	if contentEncoding != "" {
		contentLength = -1
	}

	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       buildHeadersMap(resp.Header),
		Body:          &streamingBody{reader: reader, decompressor: decompressor, raw: resp.Body, cancel: cancel},
		ContentLength: contentLength,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      proto,
	}, nil
}

// prepareOwnedConnRequest builds the *http.Request for an owned-connection
// roundtrip: preset headers and ordering first, caller headers layered on top.
// Shared by the buffered and streaming paths so their fingerprints stay
// identical.
func (t *Transport) prepareOwnedConnRequest(ctx context.Context, req *Request, proto string) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	// An explicit length overrides Go's type-sniffing of bodyReader, so a
	// streamed body can still be framed with a real Content-Length (or
	// deliberately chunked with -1) instead of forcing the caller to buffer.
	if req.BodyReader != nil && req.ContentLength != 0 {
		httpReq.ContentLength = req.ContentLength
		if req.ContentLength < 0 {
			httpReq.ContentLength = -1
			httpReq.TransferEncoding = []string{"chunked"}
		}
	}

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}
	applyPresetHeaders(httpReq, t.preset, t.getHeaderOrder(), t.getCustomPseudoOrder(), effectiveTLSOnly, proto, req.Headers)
	for key, values := range req.Headers {
		for i, value := range values {
			if i == 0 {
				httpReq.Header.Set(key, value)
			} else {
				httpReq.Header.Add(key, value)
			}
		}
	}
	return httpReq, nil
}

// splitHostPortForProto resolves the host and port used in error reporting.
func splitHostPortForProto(rawURL string) (host, port string, err error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	host = parsed.Hostname()
	port = parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return host, port, nil
}

// streamingBody is the live response body. Close tears down the decompressor,
// the wire body, and the request context, exactly once — callers routinely
// close a body twice (explicit Close plus a deferred one), and on an owned
// connection a double teardown would cancel a context that a later request on
// the same connection is already using.
type streamingBody struct {
	reader       io.ReadCloser
	decompressor io.Closer
	raw          io.ReadCloser
	cancel       context.CancelFunc
	once         sync.Once
}

func (b *streamingBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *streamingBody) Close() error {
	var err error
	b.once.Do(func() {
		if b.decompressor != nil {
			b.decompressor.Close() //nolint:errcheck
		}
		err = b.raw.Close()
		b.cancel()
	})
	return err
}
