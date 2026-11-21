# Output, exit codes and pipelines

[← back to the README](../README.md)

## Output

Plain text with no field flags is one hostname per line, so it pipes. Field
flags add bracketed columns; `-j` and `-csv` switch to JSON Lines and CSV.
CSV cells that begin with `=`, `+`, `-` or `@` are quoted, because a hostname
is attacker-influenced input and a spreadsheet executes formulas.

Results stream as they are found, so time-to-first-result is a property of the
fastest provider. `-sorted` buffers and emits in canonical order instead, which
is what you want when diffing two runs. So do `-src`, `-fam`, `-ec`, `-fs`, `-ls`
and `-a`, because who reported a name is not known until every source has answered.

With `-resolve`, each record also carries `edge` (`-eg` in plain text, the
`edge` column in CSV) when a CDN, WAF or cloud provider is in front of the
name: `{"provider", "kind", "signal", "evidence"}`. The CNAME chain is read
for every resolved name at no cost; `-cdn` adds Team Cymru's origin AS for
each distinct address, one DNS query each, and is how an edge with no
telltale CNAME is caught. A missing `edge` means not identified, not origin.
`subio resolve -cdn` does the same for a list of names, holding its output
until the batch lookup is done.

Three artifacts, each for a different job:

- **stdout** — the names, for the next tool in the pipeline.
- `-ledger` — the full evidence stream: findings, every provider observation,
  every DNS observation, and per-source diagnostics, in deterministic order.
- `-m` — a run manifest: what ran, with what limits, and what was incomplete.
  The roots are reduced to a hash, because a manifest is the artifact that gets
  attached to a ticket and the names you are researching should not travel
  with it. `-scope-id` sets a label instead.

### Exit codes

| code | meaning |
|---:|---|
| 0 | success |
| 1 | fatal error |
| 2 | configuration error; nothing was queried |
| 3 | completed, found nothing |
| 4 | completed, but at least one source's results are incomplete, or a DNS query could not be answered |

4 is the one that matters in a scheduled job. It means *do not treat this run
as a complete picture*. `subio resolve` uses the same codes: 3 when every query
completed and no name had an answer, 4 when any query could not be answered.

A bad path, flag or argument exits 2 before anything is queried or overwritten.


## In a pipeline

`subio` reads like the tools it sits beside: names on stdout, one per line,
diagnostics on stderr, and `-silent` to leave only the names. It drops into the
passive-enumeration slot of a recon pipeline.

```
subio discover example.com -silent | anew known.txt | notify
```

`-silent` keeps stderr empty, so a pipe carries names and nothing else. `anew`
sees only what is new, and `notify` only what `anew` passed on.

Feeding the resolvers and prober you already use:

```
subio discover example.com -silent | dnsx -silent -a -resp | httpx -silent -title -tech-detect
```

`subio` has its own DNS stage (`-r`) and its own TLS and HTTP probes (`-tls`,
`-web`, `-vhost`), all of which need `-active` and an authorization record. In a
chain where `dnsx` and `httpx` already do that work under their own rules, leave
subio passive and let them resolve: nothing is lost, because the names are the
same.

### The exit code is the point

Most tools in a chain exit 0 whether they found everything or nothing. `subio`
does not, and in a scheduled job that is the difference between a report and a
guess:

```sh
subio discover example.com -silent > names.txt
case $? in
  0) ;;                                        # complete
  3) echo "nothing found" >&2 ;;                # not an error, and not a result
  4) echo "INCOMPLETE: a source or a query did not answer" >&2 ;;
  *) echo "run failed" >&2; exit 1 ;;
esac
```

Without `-silent`, a run that found nothing also says why, in one line: no
source ran, every source failed (exit 4, and not an empty zone), some failed so
the absence proves nothing, every name returned was out of scope, or every
source answered and none knew a name (exit 3, which is an answer).

**4 is the one that matters.** It means a source capped, timed out or refused on
this run (a free plan's fixed row ceiling is reported but does not count),
or a DNS query went unanswered — so `names.txt` is real but partial. A diff
against yesterday's list will show names that *look* new and names that *look*
gone, and neither is a fact about the zone. Branch on 4 and you never publish
that mistake; ignore it and your pipeline will eventually report a deletion
that never happened.

For the same reason, `-ledger` is worth keeping in a job even when nothing reads
it today:

```
subio discover example.com -silent -ledger run-$(date +%F).jsonl > names.txt
```

The ledger records which source said what, when, and whether its answer was
whole. When a name shows up in a report and someone asks where it came from,
that question has an answer.
