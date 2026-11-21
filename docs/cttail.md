# Certificate transparency monitoring

[← back to the README](../README.md)

## Monitoring certificate logs

`subio cttail` monitors CT logs for hostnames in your scope, and speaks both
protocols a log can serve:

| `PROTOCOL` | What the log serves | Cost |
|---|---|---|
| `static-ct` | **names tiles**: the per-certificate subject and DNS names a tiled log (Sunlight, c2sp.org/static-ct-api) publishes as static files | just the names |
| `rfc6962` | **whole certificates** from `get-entries`, which subio parses itself | the full chain per entry |

```
subio cttail -log https://log.example -d example.com -store ./ct-state
subio cttail -logs logs.txt -d example.com -store ./ct-state
subio cttail -log https://a.example,https://b.example -d example.com -tiles 16
```

Several logs can be tailed in one run, each with its own checkpoint and its own
status line. subio asks each log which API it speaks and reads it with the right
reader; a log that answers neither is `failed`. Any log not read completely makes
the run exit 4.

An RFC 6962 log may return fewer entries than asked for — measured live,
`ct.googleapis.com` returned about 28 per request against the 64 requested while
`sabre2026h2.ct.sectigo.com` returned about 62 — so subio advances by what the
log actually returned. A reader that advanced by what it requested would skip
most of every batch and report the skipped names as absent. An entry whose
certificate cannot be parsed is counted and reported, because its names are lost:
`crypto/x509` is stricter than a log's admission policy, though no failure
appeared in 2816 entries measured across both operators.

With `-store` it records the tree size per log and, next time, reads only what
was added since — so a scheduled run costs a few requests and surfaces new
certificates. A run interrupted part-way records what it finished, so the next
one resumes there rather than starting over or skipping the gap. It is a monitor, not a backfill: the historical index that finds a
domain's existing subdomains is still `crtsh`/`crtname` under `discover`, and
`-all` (reading a whole log from the start) is a lot of bandwidth. No log
signature is verified — subio reads the names a log published, and the scope gate
drops the log's millions of unrelated names, including everything outside your
roots.


## `cttail` knows which logs exist

`subio cttail -d example.com` needs no `-log`. A snapshot of Chrome's CT log
list ships with the binary, and the run says what it chose and how old the list
is:

```
[INF] built-in list v97.0, 0 day(s) old: 17 of 89 log(s) accept certificates
      issued now (10 tiled, 7 rfc6962)
```

Two filters decide that 17. A log is read only if it accepts submissions, and
only if its temporal shard contains the moment asked about — logs are sharded
by period, and on the day this snapshot was taken 72 of the 89 could not hold a
certificate issued that day. `-log-list` takes a fresher copy, and `-log` still
picks exactly what you name.

Logs are read six at a time. They are independent and belong to different
operators, so the concurrency falls on no one provider, and reading seventeen
logs one after another spent an entire default budget on probes.
