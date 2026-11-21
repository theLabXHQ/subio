# Incremental runs and history

[← back to the README](../README.md)

## Incremental runs

`-store <dir>` gives a run a memory. Every run is diffed against what previous
runs observed, and the result is committed to an append-only log.

```
subio discover example.com -store ./state            # first run: baseline
subio discover example.com -store ./state -co -ch    # later: only what changed
subio history -store ./state -runs
subio history -store ./state -export > inventory.jsonl
```

The hard part of a subdomain diff is not finding new names. It is refusing to
claim an old one is gone. A provider that rate-limited you, lost its credential
or truncated its page did not tell you a name disappeared — it told you
nothing. A diff that treats those the same reports live assets as
decommissioned, and the first time an operator acts on that they stop trusting
the tool.

So the store records **which sources completed in each run**, and an absence is
classified against that:

| change | meaning |
|---|---|
| `new` | not in the store before |
| `reappeared` | absent from an earlier complete run, now back |
| `dns_changed` | observed again, and a resolver gave a different answer for a record type it had answered before; both sets are reported |
| `still_seen` | observed again, unchanged |
| `unconfirmed` | **not observed, and a source that knew it did not complete.** Nothing was learned. The report names the source. |
| `no_longer_observed` | not observed, and every source that had ever reported it ran and completed this time |

A worked example — `wayback` is rate-limited on the third run, and
`legacy.example.test` is the name only `wayback` ever found:

```
run2  identical inputs, all sources complete
      still_seen 3                                    conclusive: true

run3  wayback throttled
      new 1  dns_changed 1  unconfirmed 1             conclusive: false
      ~ api.example.test      A:192.0.2.1 -> A:198.51.100.9
      ! legacy.example.test   unconfirmed -- wayback did not complete

run4  wayback healthy again, legacy still absent
      no_longer_observed 1                            conclusive: true
      - legacy.example.test   no_longer_observed (missing_runs=1)
```

On run 3 subio says it does not know. On run 4, when the source that knew the
name completed and still did not return it, subio says so — and even then only
that it was not *observed*. A passive provider dropping a record is not a zone
deleting one, and the report repeats that rather than letting the phrase drift.

An incomplete run also does not advance the missing-run counter, so retention
(`-retire-after N`) can never be driven by a provider outage.

DNS gets the same treatment. A SERVFAIL, a timeout or a run without `-r` learned
nothing about the zone, so it is not a change and the stored answer stays. The
report counts those names and the run exits 4 if a lookup failed. NXDOMAIN and
NODATA are answers, and an answer that differs is a real `dns_changed`.

A run is recorded only after its results are written. If the disk is full or the
reader of your pipeline dies, the changes are reported again next time rather
than being consumed by a run nobody saw.

The store is append-only JSON lines, which is what the research's storage
decision prefers until a query pattern actually needs a database. A torn
trailing line from a crash is skipped on load and reported, not fatal, and it
costs nothing else: the next append closes it off first. `-compact` rewrites the
logs to one record per name and every readable run, which also clears that
warning; `history -export` writes it all back out, so the store is never a
one-way destination.
