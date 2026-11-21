package sources

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/theLabXHQ/subio/internal/pgwire"
	"github.com/theLabXHQ/subio/internal/sched"
	"github.com/theLabXHQ/subio/internal/source"
)

// crtShDBQuery asks for every certificate name under a domain.
const crtShDBQuery = `SELECT DISTINCT ci.NAME_VALUE
  FROM certificate_and_identities ci
 WHERE plainto_tsquery('certwatch', $1) @@ identities(ci.CERTIFICATE)
   AND (ci.NAME_VALUE = $1 OR ci.NAME_VALUE ILIKE ('%.' || $1))
 LIMIT 2000000`

// crtShDBTimeout bounds the query inside crt.sh's own server as well as on
// subio's side, so a heavy domain is cancelled by the database rather than
// left running after subio has walked away.
const crtShDBStatementTimeout = "120s"

// newCrtShDB queries crt.sh's public PostgreSQL database instead of its HTTP
// endpoint.
func newCrtShDB(ep endpoints) source.Provider {

	lim := sched.NewLimiter(6, time.Minute, 1, nil)
	return base{
		md: source.Metadata{
			ID:              "crtshdb",
			Family:          source.FamilyCT,
			Key:             source.NoKey,
			Terms:           source.TermsReviewRequired,
			TermsURL:        "https://crt.sh/",
			TermsReviewedAt: termsReviewedAt,
			DocsURL:         "https://groups.google.com/g/crtsh/about",
			Recursion:       source.RecursionFull,

			Limits: source.Limits{
				RequestsPerWindow: 6,
				Window:            time.Minute,
				Burst:             1,
				MaxPages:          1,
				RequestTimeout:    150 * time.Second,

				MaxResponseBytes: 256 << 20,
			},
			CorrelationGroup: "certificate-transparency",
			OptIn:            true,
			Note: "queries crt.sh's public PostgreSQL database directly, which returns far more " +
				"than the HTTP endpoint's capped answer but costs that shared, donated database " +
				"much more. Opt-in with -s crtshdb; one query per root, bounded by a server-side " +
				"statement timeout",
		},
		fetch: func(ctx context.Context, root string, s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {
			return crtShDBFetch(ep, lim, ctx, root, s, em)
		},
	}
}

func crtShDBFetch(ep endpoints, lim *sched.Limiter, ctx context.Context, root string,
	s *source.Session, em *emitter) (source.Status, source.ErrorClass, error) {

	if err := lim.Wait(ctx); err != nil {
		return source.StatusCancelled, source.ErrDeadline, err
	}
	qctx, cancel := context.WithTimeout(ctx, em.md.Limits.RequestTimeout)
	defer cancel()

	allowPlaintext := os.Getenv(crtShDBPlaintextEnv) == "1"
	conn, err := pgwire.Connect(qctx, pgwire.Config{
		Addr: ep.crtshdb, User: "guest", Database: "certwatch",

		AppName:        "subio",
		TLS:            &tls.Config{ServerName: hostOf(ep.crtshdb), MinVersion: tls.VersionTLS12},
		AllowPlaintext: allowPlaintext,
	})
	em.sum.Requests++
	if err != nil {
		if errors.Is(err, pgwire.ErrPasswordRequired) {

			return source.StatusFailed, source.ErrUnauthorized, err
		}
		if errors.Is(err, pgwire.ErrTLSVerify) {
			em.Note("the database's TLS certificate does not verify, so subio did not query it. Set " +
				crtShDBPlaintextEnv + "=1 to query it unauthenticated, accepting that anyone on the " +
				"path could alter the names it returns")
			return source.StatusFailed, source.ErrTransport, err
		}
		return source.StatusFailed, source.ErrTransport, err
	}
	defer conn.Close()
	if !conn.UsingTLS() {
		em.Note("queried over an unauthenticated connection (" + crtShDBPlaintextEnv +
			" is set), so these names were not protected from alteration in transit")
	}

	if err := conn.Exec(qctx, "SET statement_timeout = '"+crtShDBStatementTimeout+"'"); err != nil {
		return source.StatusFailed, source.ErrTransport, err
	}

	rows := 0
	var bytesKept int64
	budget := em.md.Limits.MaxResponseBytes
	err = conn.Query(qctx, crtShDBQuery, []any{root}, func(cols [][]byte) error {
		rows++
		if bytesKept > budget {

			return errCrtShDBBudget
		}
		if len(cols) == 0 || cols[0] == nil {
			em.Unusable()
			return nil
		}

		name := strings.TrimSpace(string(cols[0]))
		if name == "" {
			em.Unusable()
			return nil
		}
		bytesKept += int64(len(name))
		host, wild := stripWildcard(name)
		var attrs map[string]string
		if wild {
			attrs = map[string]string{"wildcard_certificate": "true"}
		}

		em.Observe(host, "certificate-san", "", "", time.Time{}, attrs)
		return nil
	})
	em.sum.Pages++
	if errors.Is(err, errCrtShDBBudget) {
		return source.StatusTruncated, source.ErrOversize, nil
	}
	if err != nil {
		var pe *pgwire.Error
		if errors.As(err, &pe) && pe.Code == "57014" {
			em.Note("crt.sh cancelled the query at its own statement timeout; this domain's " +
				"certificate history is too large for the guest database interface")

			return failureStatus(em, source.ErrDeadline), source.ErrDeadline, err
		}
		return failureStatus(em, source.ErrTransport), source.ErrTransport, err
	}
	if rows == 0 {
		return source.StatusEmpty, source.ErrNone, nil
	}
	return source.StatusComplete, source.ErrNone, nil
}

// crtShDBPlaintextEnv is the explicit opt-in to an unauthenticated connection.
const crtShDBPlaintextEnv = "SUBIO_CRTSHDB_ALLOW_PLAINTEXT"

// errCrtShDBBudget stops consumption when the retained-name budget is spent.
var errCrtShDBBudget = errors.New("crtshdb: name budget exhausted")

// hostOf strips the port from host:port, for the TLS server name.
func hostOf(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return addr[:i]
	}
	return addr
}
