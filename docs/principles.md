# Principles: what subio reports, and what it will not do

[← back to the README](../README.md)

## Why another one

Most subdomain tools answer one question: *what names exist?* They answer it
well. subio answers three more that matter once you act on the output:

**Where did this name come from?** Every hostname joins to the provider
observations that produced it, with the provider's own stated time preserved
and `null` when it stated none. A certificate SAN, an archived URL and a
passive-DNS record are different kinds of evidence, and they stay different.
[SCHEMA.md](../SCHEMA.md) is the field contract for those records, so something
other than subio can read them.

**What did I fail to see?** Every adapter terminates with a typed status.
`complete` and `empty` mean subio read the provider's whole answer. `truncated`,
`partial`, `throttled`, `timed_out`, `failed`, `missing_credentials` and
`terms_blocked` mean it did not, and subio exits 4 to say so. A tool that
collapses these into "found N names" will eventually tell you an asset was
decommissioned when a provider was simply rate-limiting you.

There is a third thing a status cannot say, and pretending otherwise was a real
defect here. Whether the provider's answer was the *whole truth* is the
provider's property, not subio's. crt.sh's HTTP endpoint returns far less than
its own database holds, with nothing in the response to say so — 21 names
against 2334 for the same domain, both runs reporting `complete`
(the measurement). Such a source is now
marked `caps_silently` in the ledger, and the run says in plain words that
`complete` meant the whole answer was read, not that the answer was whole, and
names the remedy (`-s crtshdb`). It does not change the exit code: the status is
true about what was read. Adapters whose provider documents a numeric cap —
`subdomaincenter` at 500 names, `netlas` at 10 000, `scanmalware`, `github` —
already report `truncated` when they reach it, so they need no caveat.

Interrupting a run keeps that promise instead of breaking it. Ctrl-C stops the
work, writes the ledger, manifest and store from what was collected, prints each
source's real status — `cancelled` for the ones still in flight — and exits 4.
A second Ctrl-C leaves at once and says the artifacts are incomplete. `SIGTERM`
takes the same path, so a scheduler stopping a job does not look like a crash.

A provider that answers 200 with nothing readable (a maintenance page, an error
object, a renamed field, a compressed stream) is `failed (schema_drift)`, not
`empty`. Only a response in the format the adapter understands can say a domain
has no names.

**Which provider is worth its cost?** The run report's `ONLY-HERE` column is
*exclusive* contribution: names no other selected source reported. It is
computed after every adapter finishes, so unlike a running marginal count it
does not depend on which goroutine happened to return first.

**And how do I reach what no index holds?** Passive sources converge, because
they all read the same upstream data. The names nobody's index has are found by
asking DNS and the target's own servers — guessing, offline NSEC3 walking,
reading a host's content, probing virtual hosts — and subio runs those too,
behind an explicit authorization. See [The DNS stage](dns.md#the-dns-stage),
[Finding names no index holds](active.md#finding-names-no-index-holds) and
[Monitoring certificate logs](cttail.md#monitoring-certificate-logs).

Every keyless adapter has answered live runs, and the numbers quoted with a date
come from them; the rest come from hermetic, loopback-only tests. Field recall
against a zone whose true contents are known, and a keyed cross-tool comparison,
still need an owner-controlled zone and API keys.


## What subio will not do

- Claim a discovered name is live, owned, in scope or vulnerable.
- Send a guessed name anywhere without `-active` and a record that allows it.
- Expand a wildcard certificate into guessed child names.
- Rotate credentials to get past a documented rate limit.
- Send a request for a provider whose terms the active profile has not cleared.
- Treat a resolver failure as proof a name does not exist.
- Report a truncated result set as a complete one.


## What subio will not do, and why

Two techniques in common use are deliberately absent, and the research behind
the 2026-11-13 note confirmed both should stay absent.

**Cloud bucket and endpoint name guessing.** Trying `acme-backups.s3.amazonaws.com`
or `acme.workers.dev` is brute force in *the provider's* namespace, against
names the target never published. The Cloudflare case makes it sharpest: a
`workers.dev` label is an account username in Cloudflare's own zone, not a name
your target controls. subio enumerates under roots an operator supplied and
nothing else.

**Prefix-wide reverse-DNS sweeps.** Reading PTR for every address in a netblock
touches addresses that belong to whoever else is in it; bbot flags its own
equivalent `loud`. `-ptr` reads the addresses subio actually found, and a sweep
over a prefix is allowed only when the authorization record names that prefix.

Both lines come from the same rule as the rest of the tool: discovery never
widens authorization. `relate` suggests a related root and refuses to enumerate
under it for the same reason.


## On a terminal

A run that a person is watching opens with the wordmark, in the same slant style
and the same bold-plus-dim treatment as [Pulse](https://github.com/theLabXHQ/pulse),
because the two are one family:

```
               __    _
   _______  __/ /_  (_)___
  / ___/ / / / __ \/ / __ \
 (__  ) /_/ / /_/ / / /_/ /
/____/\__,_/_.___/_/\____/

                 thelabx.io
```

It goes to stderr, and **only** when stderr is a terminal and `-silent` is off,
so a pipeline, a log file and the test harness never see it. That condition is
the whole reason a banner is acceptable in a tool whose output is meant to be
piped: it is for the person watching, and it disappears the moment anything else
is reading. `-nc` turns the colour off and keeps the shape.

The run closes the same way Pulse's does, with a dim tag and the count in bold:

```
[subio] 2 hostnames, 2 evidence records in 60ms
[subio] 2 resolved, 0 flagged wildcard-synthesized
```

Red appears on that line only when a source was incomplete, which is the one
thing on it worth interrupting someone for. Without colour the text is
unchanged.
