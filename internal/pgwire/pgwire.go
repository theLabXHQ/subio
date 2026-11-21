// Package pgwire is a minimal PostgreSQL v3 wire-protocol client, enough to
// run a read-only parameterised query against a public database.
package pgwire

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	// protocolVersion is 3.0, the only version this speaks.
	protocolVersion = 196608
	// sslRequestCode asks the server to start TLS before the startup message.
	sslRequestCode = 80877103
	// maxMessage bounds one server message, so a hostile or broken server cannot
	// make the client allocate without limit.
	maxMessage = 64 << 20
)

// Error is a PostgreSQL ErrorResponse.
type Error struct {
	Severity string
	Code     string
	Message  string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("postgres: %s %s: %s", e.Severity, e.Code, e.Message)
	}
	return "postgres: " + e.Message
}

// ErrPasswordRequired reports a server that wants an authentication method
// this client does not implement.
var ErrPasswordRequired = errors.New("pgwire: server requested password authentication, which this client does not implement")

// ErrTLSVerify reports a server whose TLS certificate did not verify.
var ErrTLSVerify = errors.New("pgwire: server TLS certificate did not verify")

// Config parameterises a connection.
type Config struct {
	// Addr is host:port.
	Addr string
	// User and Database are the startup parameters.
	User     string
	Database string
	// AppName is reported to the server, so the operator of a shared database
	// can see who is querying it.
	AppName string

	// TLS, when non-nil, is used if the server accepts a TLS request.
	TLS *tls.Config

	// AllowPlaintext permits continuing without TLS when verification fails.
	AllowPlaintext bool
	// ConnectTimeout bounds the dial and handshake.
	ConnectTimeout time.Duration
}

// Conn is one connection.
type Conn struct {
	c net.Conn
	r *bufio.Reader
	// w buffers outgoing messages and marks holds the offset of each pending
	// message's length field, so Parse/Bind/Execute/Sync go out in one write.
	w     []byte
	marks []int
	tls   bool
}

// Connect dials, optionally starts TLS, and completes the startup handshake.
func Connect(ctx context.Context, cfg Config) (*Conn, error) {
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 20 * time.Second
	}
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("pgwire: dial %s: %w", cfg.Addr, err)
	}
	c := &Conn{c: raw, r: bufio.NewReaderSize(raw, 64<<10), w: make([]byte, 0, 1024)}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	}

	if cfg.TLS != nil {
		upgraded, err := c.startTLS(cfg.TLS)
		switch {
		case err == nil:
			c.tls = upgraded
		case errors.Is(err, ErrTLSVerify) && cfg.AllowPlaintext:

			_ = raw.Close()
			if c, err = redialPlaintext(ctx, cfg); err != nil {
				return nil, err
			}
		default:
			_ = raw.Close()
			return nil, err
		}
	}
	if err := c.startup(cfg); err != nil {
		_ = c.c.Close()
		return nil, err
	}
	return c, nil
}

// redialPlaintext opens a fresh connection with no TLS, for the caller that
// explicitly accepted an unauthenticated channel.
func redialPlaintext(ctx context.Context, cfg Config) (*Conn, error) {
	d := net.Dialer{Timeout: cfg.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("pgwire: dial %s: %w", cfg.Addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	} else {
		_ = raw.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	}
	return &Conn{c: raw, r: bufio.NewReaderSize(raw, 64<<10), w: make([]byte, 0, 1024)}, nil
}

// UsingTLS reports whether the connection was upgraded, so a caller can
// record it rather than assume.
func (c *Conn) UsingTLS() bool { return c.tls }

// startTLS sends an SSLRequest and upgrades when the server agrees.
func (c *Conn) startTLS(tc *tls.Config) (bool, error) {
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], sslRequestCode)
	if _, err := c.c.Write(req[:]); err != nil {
		return false, fmt.Errorf("pgwire: ssl request: %w", err)
	}
	reply, err := c.r.ReadByte()
	if err != nil {
		return false, fmt.Errorf("pgwire: ssl reply: %w", err)
	}
	if reply != 'S' {

		return false, nil
	}
	tlsConn := tls.Client(c.c, tc)
	if err := tlsConn.Handshake(); err != nil {
		return false, fmt.Errorf("%w: %v", ErrTLSVerify, err)
	}
	c.c = tlsConn
	c.r = bufio.NewReaderSize(tlsConn, 64<<10)
	return true, nil
}

// startup sends the StartupMessage and reads until the server is ready.
func (c *Conn) startup(cfg Config) error {
	params := [][2]string{{"user", cfg.User}}
	if cfg.Database != "" {
		params = append(params, [2]string{"database", cfg.Database})
	}
	if cfg.AppName != "" {
		params = append(params, [2]string{"application_name", cfg.AppName})
	}
	body := make([]byte, 4, 128)
	binary.BigEndian.PutUint32(body[0:4], protocolVersion)
	for _, kv := range params {
		body = append(body, kv[0]...)
		body = append(body, 0)
		body = append(body, kv[1]...)
		body = append(body, 0)
	}
	body = append(body, 0)
	// The startup message has no type byte.
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)+4))
	if _, err := c.c.Write(append(hdr[:], body...)); err != nil {
		return fmt.Errorf("pgwire: startup: %w", err)
	}

	for {
		t, payload, err := c.read()
		if err != nil {
			return err
		}
		switch t {
		case 'R':
			if len(payload) < 4 {
				return errors.New("pgwire: short authentication message")
			}
			switch binary.BigEndian.Uint32(payload[0:4]) {
			case 0:
			default:
				return ErrPasswordRequired
			}
		case 'S', 'K', 'N':
		case 'Z':
			return nil
		case 'E':
			return parseError(payload)
		default:
			return fmt.Errorf("pgwire: unexpected message %q during startup", t)
		}
	}
}

// Exec runs a statement with no result rows, through the simple query
// protocol.
func (c *Conn) Exec(ctx context.Context, sql string) error {
	c.deadline(ctx)
	c.begin('Q')
	c.cstring(sql)
	if err := c.flush(); err != nil {
		return err
	}
	for {
		t, payload, err := c.read()
		if err != nil {
			return err
		}
		switch t {
		case 'C', 'S', 'N', 'T', 'D':
		case 'Z':
			return nil
		case 'E':

			perr := parseError(payload)
			c.drainToReady()
			return perr
		default:
			return fmt.Errorf("pgwire: unexpected message %q during exec", t)
		}
	}
}

// Query runs one parameterised statement and calls row for each result row.
func (c *Conn) Query(ctx context.Context, sql string, params []any, row func(cols [][]byte) error) error {
	c.deadline(ctx)

	c.begin('P')
	c.cstring("")
	c.cstring(sql)
	c.int16(0)

	c.begin('B')
	c.cstring("")
	c.cstring("")
	c.int16(0)
	c.int16(len(params))
	for _, p := range params {
		switch v := p.(type) {
		case nil:
			c.int32(-1)
		case string:
			c.int32(len(v))
			c.w = append(c.w, v...)
		case []byte:
			c.int32(len(v))
			c.w = append(c.w, v...)
		default:
			s := fmt.Sprint(v)
			c.int32(len(s))
			c.w = append(c.w, s...)
		}
	}
	c.int16(0)

	c.begin('E')
	c.cstring("")
	c.int32(0)
	c.begin('S')
	if err := c.flush(); err != nil {
		return err
	}

	var queryErr error
	for {
		t, payload, err := c.read()
		if err != nil {
			return err
		}
		switch t {
		case '1', '2', 'T', 'C', 'S', 'N', 'n', 's':
		case 'D':
			cols, derr := parseDataRow(payload)
			if derr != nil {
				return derr
			}
			if queryErr == nil {
				if rerr := row(cols); rerr != nil {

					queryErr = rerr
				}
			}
		case 'Z':
			return queryErr
		case 'E':
			if queryErr == nil {
				queryErr = parseError(payload)
			}
		default:
			return fmt.Errorf("pgwire: unexpected message %q during query", t)
		}
	}
}

// Close sends Terminate and closes the socket.
func (c *Conn) Close() error {
	c.begin('X')
	_ = c.flush()
	return c.c.Close()
}

// drainToReady reads until ReadyForQuery, ignoring everything, so a
// connection is usable after a failed statement.
func (c *Conn) drainToReady() {
	for i := 0; i < 1000; i++ {
		t, _, err := c.read()
		if err != nil || t == 'Z' {
			return
		}
	}
}

func (c *Conn) deadline(ctx context.Context) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.c.SetDeadline(dl)
	}
}

// begin starts a new client message of the given type, flushing nothing: the
// buffer may hold several messages, which is how Parse/Bind/Execute/Sync are
// sent in one write.
func (c *Conn) begin(t byte) {
	c.w = append(c.w, t)

	c.w = append(c.w, 0, 0, 0, 0)
	c.marks = append(c.marks, len(c.w)-4)
}

func (c *Conn) cstring(s string) {
	c.w = append(c.w, s...)
	c.w = append(c.w, 0)
}

func (c *Conn) int16(v int) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	c.w = append(c.w, b[:]...)
}

func (c *Conn) int32(v int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(int32(v)))
	c.w = append(c.w, b[:]...)
}

// flush fills in every pending message length and writes the buffer.
func (c *Conn) flush() error {

	for i, at := range c.marks {
		end := len(c.w)
		if i+1 < len(c.marks) {
			end = c.marks[i+1] - 1
		}
		binary.BigEndian.PutUint32(c.w[at:at+4], uint32(end-at))
	}
	c.marks = c.marks[:0]
	_, err := c.c.Write(c.w)
	c.w = c.w[:0]
	if err != nil {
		return fmt.Errorf("pgwire: write: %w", err)
	}
	return nil
}

// read returns one server message's type and payload.
func (c *Conn) read() (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return 0, nil, fmt.Errorf("pgwire: read header: %w", err)
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if n < 4 || n-4 > maxMessage {
		return 0, nil, fmt.Errorf("pgwire: message length %d out of range", n)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return 0, nil, fmt.Errorf("pgwire: read body: %w", err)
	}
	return hdr[0], payload, nil
}

// parseDataRow splits a DataRow into its columns.
func parseDataRow(p []byte) ([][]byte, error) {
	if len(p) < 2 {
		return nil, errors.New("pgwire: short data row")
	}
	n := int(binary.BigEndian.Uint16(p[0:2]))
	cols := make([][]byte, 0, n)
	off := 2
	for i := 0; i < n; i++ {
		if off+4 > len(p) {
			return nil, errors.New("pgwire: data row runs past its end")
		}
		l := int(int32(binary.BigEndian.Uint32(p[off : off+4])))
		off += 4
		if l < 0 {
			cols = append(cols, nil)
			continue
		}
		if off+l > len(p) {
			return nil, errors.New("pgwire: data row column runs past its end")
		}
		cols = append(cols, p[off:off+l])
		off += l
	}
	return cols, nil
}

// parseError reads an ErrorResponse's fields.
func parseError(p []byte) *Error {
	e := &Error{}
	for len(p) > 0 {
		code := p[0]
		if code == 0 {
			break
		}
		p = p[1:]
		i := strings.IndexByte(string(p), 0)
		if i < 0 {
			break
		}
		val := string(p[:i])
		p = p[i+1:]
		switch code {
		case 'S':
			e.Severity = val
		case 'C':
			e.Code = val
		case 'M':
			e.Message = val
		}
	}
	if e.Message == "" {
		e.Message = "unspecified error"
	}
	return e
}
