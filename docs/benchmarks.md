# Benchmarks and comparisons

[← back to the README](../README.md)

## Comparing against other tools

These figures come from a comparison harness used while subio was built; it is
a development instrument and is not part of the released tool. It ran real
enumerators side by side: subio,
subfinder, assetfinder, waybackurls, gau and github-subdomains. It reported
unique names, exclusive contribution, time-to-first-result, wall time, peak
RSS, CPU time and rejected output per tool, plus the pairwise Jaccard overlap
of the median runs.

It **required an authorization record** and refused to run without one, because
every tool in that list queries third-party services about a real domain. The
same record gates subio's active methods today.

The record names what the run actually is, and the three methods are not
interchangeable:

| method | what it covers | whose permission it needs |
|---|---|---|
| `public-data` | certificate transparency logs, web archives, crawl indexes | nobody's: no packet reaches the target, and RFC 9162 says CT logs should not impose conditions on retrieving their data |
| `passive-providers` | the above plus credentialed provider APIs | each provider's terms |
| `active-dns` | queries to the target's own nameservers | **the target owner's** |

That split matters. An earlier version of this gate required a claim of
authority over the target before it would read a public CT log — which meant
the only way to satisfy it was to write something untrue. A control that can
only be satisfied by lying is not a control. So a `public-data` record attests
to something narrower and accurate: who is running it, over what names, that
collection is public-dataset only, and that no authority over the target is
claimed. Every report prints that sentence, so the record cannot later be read
as a grant from the target.

A misspelled method is refused rather than silently narrowing what the record
covers.


```json
{
  "owner": "who authorized this",
  "scope": ["example.com"],
  "granted_at": "2026-11-01",
  "expires_at": "2026-12-01",
  "stop_contact": "soc@example.com",
  "allowed_methods": ["passive-providers"]
}
```

A template to fill in is at `examples/authorization.template.json`. Fill it in
yourself: the record exists to state that someone with authority over those
domains permitted the run, so one written by anybody else attests to nothing.

The scope check uses the same dot boundary as discovery, so an authorization
for `example.com` does not cover `notexample.com`. An expired record is
refused. A tool whose credential is absent is recorded as skipped rather than
run, because a tool without its API keys produces an empty result that would
read as poor coverage.

Given a known inventory, the harness reported coverage of it, and labelled it
coverage rather than recall. Without it there is no coverage figure
at all: a union of tool output is not ground truth, because it cannot
distinguish a name every tool missed from a name that does not exist.

### Measured against other tools

Against google.com, every tool keyless, one repetition:

| tool | unique | only-here | first result | wall | peak RSS | exit |
|---|---:|---:|---:|---:|---:|---:|
| subfinder | 170 062 | 964 | 20.9s | 21.2s | 169 MB | 0 |
| **subio** | 169 099 | 0 | **0.44s** | 41.4s | 182 MB | 4 |
| assetfinder | 53 | 0 | 1.0s | 1.4s | 32 MB | 0 |
| gau | 2 | 0 | 1m33s | 5m (timed out) | 32 MB | -1 |
| waybackurls | 0 | 0 | never | 0.5s | 9 MB | 0 |

Read it honestly. Coverage is at parity, not ahead — 0.57% behind, with zero
exclusive names, because both tools lean on the same certificate-transparency
index. Memory is 8% worse. Wall time is slower than subfinder because subio
gives a failing archive two bounded attempts before reporting `partial` and
exiting 4, where subfinder gives it less rope and exits 0.

What is actually better is time to first result — 442 ms against 20.9 s,
because results stream as they arrive instead of being sorted at the end — and
what the exit code tells you. In that run `waybackurls` returned nothing and
exited 0, and `gau` spent five minutes and exited -1 with two names. A
scheduled job reading exit codes would have recorded both as successful.

One domain, one run, no credentials, no ground truth. It is a configuration
result, not a verdict.

Two things have changed since that run and it has not been repeated. Every keyless
run exited 4 back then, because adapters with no key counted as incomplete, so
subio's 4 in that table did not by itself show a failure was detected; a healthy
keyless run now exits 0. And a timed-out archive now costs one 30-second budget
instead of two.
