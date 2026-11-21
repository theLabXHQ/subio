# Sources, credentials and terms

[← back to the README](../README.md)

## Sources

Twenty-two adapters, each written against the provider's documented interface with
the documented limit recorded in code rather than discovered by probing:

| adapter | family | key | documented limit |
|---|---|---|---|
| `crtsh` | certificate transparency | — | not published; queried gently |
| `crtshdb` | certificate transparency | — | not published; **opt-in**, queries crt.sh's PostgreSQL database |
| `crtname` | certificate transparency | — | 100 requests per IP per day |
| `anubis` | aggregated index | — | not published |
| `hackertarget` | passive DNS | optional | 50 calls/day on the free tier |
| `certspotter` | certificate transparency | required | 10 full-domain queries/hour (Small plan) |
| `wayback` | web archive | — | not published |
| `commoncrawl` | web archive | — | not published; limited data licence |
| `github` | code search | required | 10 req/min, 1000 results/search |
| `securitytrails` | passive DNS | required | monthly quota; ~1s throttle reset |
| `chaos` | curated dataset | required | not published |
| `netlas` | scan engine | required | 60/min, 20/page, 10 000-result ceiling |
| `shodan` | scan engine | required | plan-dependent credits |
| `censys` | scan engine | required | 25 req/s per IP; 100/page, each extra page one credit |
| `fofa` | scan engine | required | F-points or free quota; 10 000-result ceiling |
| `scanmalware` | certificate transparency | — | 12 000/min anonymous; 5000 names per query |
| `shodanct` | certificate transparency | — | not published |
| `subdomaincenter` | aggregated index | — | 500 random results per query; personal use only |
| `thc` | passive DNS | — | 250-token burst, 0.5 tokens/s per IP |
| `dnsrepo` | passive DNS | — | not published; an HTML page whose keyless answer stops at 150 names |
| `sitedossier` | aggregated index | — | not published; **opt-in**, an HTML listing that blocks automated clients after a few pages |
| `urlscan` | scan engine | — | 30/min per IP, read from its rate-limit headers |

Every keyless adapter in this table has answered a live default run, on
kernel.org, mozilla.org and wikipedia.org on 2026-11-21.

`dnsrepo` and `sitedossier` were added that day for the keyless run, measured
against it first. On mozilla.org dnsrepo added 30 names no other source had
and sitedossier 14, and 35 of those 45 resolved. Within minutes sitedossier
was redirecting subio and returning 403 to a browser from the same address,
so it runs only when named with `-s`. The seven that need a
key - `censys`, `chaos`, `fofa`, `github`, `netlas`, `securitytrails` and
`shodan` - have **not** been run against their live APIs: their response
formats come from provider documentation, official clients and subfinder's
source, and the hermetic suite checks them against those formats only.

`censys` and `fofa` in particular were written without any live answer. `censys`
uses the Platform API v3 (the legacy v2 answered 404 when it was written) with
a personal access token, and its response shape is the one in Censys's own Go
SDK; the query `cert.names: "<root>"` relies on the documented subdomain
analyzer for that field, with no documented example to confirm it. FOFA's
documentation renders only in a browser, so `fofa` follows FofaInfo's official
client: key-only authentication, errors reported in a 200 body, and rows that
may carry a scheme and a port, which are stripped.

`crtname` is the one that carries a first-seen timestamp per name, so it is
where the ledger's provider-stated times usually come from. It is also
certificate-transparency derived, and shares `crtsh`'s correlation group: the
two agreeing is one evidence family agreeing with itself, not independent
confirmation.

More adapters is not the same as more coverage, and the run report will tell
you so. Measured on google.com: adding `anubis` and `hackertarget` took the run
from 169 093 names to 169 099. Six names. `anubis` reported 5 180 in-scope
names and contributed **none** that another selected source had not already
found; `hackertarget` reported 51 and contributed 6.

They are still worth having. Both are a different evidence family from
certificate transparency, so on a domain with little TLS history their share
should be larger, and 5 180 names corroborated by a second family is worth
something to a ledger whose job is recording who said what. But corroborating
and contributing are different, and the `UNIQUE` and `ONLY-HERE` columns keep
them apart so they cannot be mistaken for each other.

Three adapters are left out of the default run for what they cost: `wayback`,
`commoncrawl` and `certspotter`. On live default runs on kernel.org and
mozilla.org (2026-11-21), wayback took 263 seconds, certspotter 362, and
commoncrawl failed after 44 on both. Between them they added two names no
other source had, and they set the run at six minutes. Without them a default
run ends when crt.sh does. `-all-sources` (`-as`) adds them back, and naming
one with `-s` always runs it.

hackertarget without a key stops at 50 rows on every domain big enough to
have more. That is reported as `truncated (plan_limit)`, and it does not make
the run exit 4: a cap that every keyless run hits identically says nothing
about this run, and an exit code that is 4 every time tells you nothing. A
later diff still treats what it did not return as unknown, never as gone.

`subio sources` lists them offline with their credential and terms state. It
never validates a credential: a live "health check" is a request you did not
ask for, and some providers bill it.

Two providers are deliberately absent. VirusTotal's public API and WhoisXML
API's default terms (§4.6.1) both forbid use in a commercial product, so
shipping an adapter for them would be shipping a trap.

### Credentials

`SUBIO_KEY_<ADAPTER>` in the environment, or a file of `adapter = value`
lines passed to `-sf`. The file must not be readable by other users; subio
refuses it otherwise. Common names already in your shell (`GITHUB_TOKEN`,
`SHODAN_API_KEY`, …) are picked up as fallbacks.

An adapter that needs a key you have not configured does not run, and subio says
which ones were left out. It only counts as incomplete if you named it with `-s`,
so a healthy keyless run exits 0.

A credential never reaches a log line, an error message, a cache key or an
evidence record. Shodan accepts its key only as a URL parameter; that URL is
redacted everywhere it could be printed.

It does not reach another host either. A provider's redirect to a different host,
or from HTTPS to HTTP, is refused and reported as `redirect_refused`, because
following it would carry the key along in a header or a `Referer`.

### Terms profiles

`-p personal` (the default) runs adapters whose data-use rights are merely
unresolved. `-p commercial` runs only adapters whose terms explicitly permit
commercial retention, caching and automated access.

Today that is none of them, so `-p commercial` enables nothing. That is the
correct fail-closed answer, not a bug: of 54 provider pages reviewed on
2026-10-31, not one granted all three. Clear a provider against your own
contract and mark its reviewed state before enabling it.
