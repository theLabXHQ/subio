# The DNS stage

[← back to the README](../README.md)

## The DNS stage

`-r` turns on DNS observation. It is **active**: it queries the nameservers
responsible for the names you found. Use it only where you are authorized to. A
CNAME pointing at another name under your root becomes a finding too, since the
answer already paid for it.

The resolver is built for the shape of this workload — hundreds of thousands of
*distinct* names, one query each, nothing for a cache to amortize:

- one UDP socket per worker with a window of outstanding queries, so a worker
  is not capped at one query per round trip;
- zero allocations on the query and parse paths;
- a response is accepted only when it comes from the server that was asked and
  its transaction id **and** question name match an outstanding query;
- **DNS-0x20**: every query name goes out with the case of its letters chosen at
  random, and the reply has to echo it. The transaction id and source port give
  an off-path attacker about 32 bits to guess; `api.example.com` adds thirteen
  more, one per letter, and costs nothing on the wire because the same name in
  different case is the same name. A resolver that lowercases the question gives
  the check nothing to verify — its answers are **kept**, and the run names it,
  because dropping them would cost you every name that resolver holds. `-no-0x20`
  turns it off;
- EDNS0 on every query, so fewer answers truncate; TCP re-ask when, and only when,
  the answer sets `TC`, beside the pipeline so it does not stall other queries.
  A resolver that rejects EDNS with a `FORMERR` carrying no OPT record of its
  own is re-asked plain, once, and remembered as no-EDNS so the fallback costs
  one query per resolver rather than one per name; a `FORMERR` that does carry
  OPT is an error, not a reason to strip the DO bit the RRSIG proof needs;
- a SERVFAIL or REFUSED is asked again on another resolver before it counts;
- each resolver is checked first against a name under `.invalid`, which no zone
  receives, and one that invents an answer or never replies is dropped. One that
  later mostly times out - judged on its last few dozen queries, not the whole
  run, so a resolver that answered for an hour and then died is noticed at once -
  is benched for 30 seconds and then asked again, and the manifest records how
  each behaved;
- with two or more resolvers, a name a source reported that one resolver calls
  `NXDOMAIN` is asked of a different one. A source naming it is evidence it
  exists, so one filtering or stale resolver does not get the last word: an
  answer overturns the denial, and the disagreement is kept in the ledger with
  the denier named;
- `-rqps` caps each resolver's own query rate, so a global ceiling split over a
  public list cannot push one resolver past its limit and get the run throttled
  or served rate-limited wrong answers;
- `-authoritative` reads each root's NS and their addresses, then queries those
  nameservers directly — no recursive resolver in between to lie, rate-limit or
  serve a stale cache entry. All load then lands on the target, so it belongs
  under the same authorization as the rest of active discovery. **Lower `-qps`
  when you use it**: a zone's own nameservers rate-limit harder than a public
  recursive. Measured on `kernel.org`, the same 500-odd queries answered 100% at
  `-qps 50` and 37.5% at the default, the rest timing out — and a timeout is not
  a better answer than a cached one, it is no answer;
- a negative answer is not always a fresh one. When a resolver marks a
  `NXDOMAIN` as coming from its own cache or synthesis (EDE `synthesized`,
  `stale answer`, `stale nxdomain answer`), the ledger records
  `denial_inferred` and the run says how many names rest on it. On `kernel.org`
  that was 57 names whose non-existence nothing had asked the zone about. It
  does not change the exit code: the `NXDOMAIN` was real and subio read it
  correctly. What it cannot support is the inference that the zone was
  consulted. To re-ask a list of such names, point `-rs` at the zone's own
  nameservers rather than reaching for `-authoritative`, which `discover` has
  and `resolve` does not:

  ```
  subio resolve -l names.txt -rs 43.247.171.1 -ty A -qps 20
  ```

  Checked against `kernel.org`: twelve names its resolver had denied from
  cache were denied again by its own nameserver, so on that sample the cached
  answers were right. A cached denial being weaker evidence is not the same as
  it being wrong, and one sample settles neither;
- `SERVFAIL`, `REFUSED` and timeout are errors. Only `NXDOMAIN` and an empty
  `NOERROR` are negative answers. Nothing else is allowed to become "does not
  exist";
- when a resolver attaches an **Extended DNS Error** (RFC 8914) the run says
  what it was. A filtered name, a bogus signature, a prohibited zone and a
  resolver having a bad moment are four facts that otherwise arrive as the one
  word `servfail`:

  ```
  The resolvers gave reasons: filtered (12), dnssec bogus (3), prohibited (1).
  ```

  Three codes get a warning of their own, because they arrive with `NOERROR`
  and an answer: `forged answer`, `synthesized` and `stale answer` each say the
  records you were handed may not be what the zone publishes;
- **losses this machine caused are not reported as the network's.** At high
  query rates the kernel discards datagrams that already arrived, and they look
  exactly like a query nobody answered. The count comes from `/proc/net/udp`,
  so a run can tell you to lower `-qps` instead of blaming the zone:

  ```
  [WRN] this machine discarded 4217 datagram(s) before subio could read them, so
  some of the timeouts above are local loss rather than an unanswered query; a
  lower -qps recovers them
  ```

  On a platform without that counter nothing is claimed. "0 dropped" where it
  cannot be known is the kind of statement this tool exists not to make.

### A resolver list that learns

`-rpo profile.json` writes what the run learned about each resolver, and
`-rp profile.json` reads it back on the next run (`discover`, `all` and
`resolve`). Each resolver gets a verdict with the numbers behind it:

- `drop`: it answered a name under `.invalid` (a hijacker), it mostly timed
  out, or it returned the question with its case changed, so DNS-0x20 verifies
  nothing it answers. It is left out of the next run, and stays in the next
  profile with its original date so it does not drift back in.
- `slow`: it refused at speed, and `sustainable_qps` is the rate it tolerated
  after throttling. The next run starts it there, inside `-rqps`.
- `use`, or `unmeasured` for one this run sent nothing to.

A resolver the profile does not name is used; a profile that would drop every
resolver given is ignored, with a warning, rather than leaving nothing to ask.
Validators test a list once at low concurrency; what matters under load only
shows in a real run, which is where this is measured.

### Not asking what a denial already answered

When a resolver answers NXDOMAIN with the zone's SOA, subio believes it for the
SOA's negative TTL (RFC 2308), and reads it as RFC 8020 does: nothing exists
beneath a name that does not exist. A later query for that name, or for any
name under it, is answered NXDOMAIN without being sent, and says so -
`inferred_from` in `resolve -j` and in the ledger names the denial it rests on.
A zone has to earn this. The first two such queries are sent anyway and must
come back NXDOMAIN, and one in sixteen still is after that; a zone that turns
out to have a name beneath a denial is never inferred from again in that run.
A zone that passes every check and still breaks the rule for a name that was
inferred would lose that name; `-nnc` asks every query.

### Wildcards

`*.example.com` answering everything is the main way a subdomain tool produces
thousands of fake findings. subio probes each zone level with independent
random labels, and when a name's answer is indistinguishable from what the
parent synthesizes it marks the name `wildcard_suspected` **and keeps the
control samples that produced the verdict**. A wildcard behind a load balancer
answers from a rotating pool, so subio asks more controls until it has mapped the
pool, and a name is explained only if every record it has came from there.

It does not delete the name. A randomized control can collide with a real
answer, a wildcard can differ by record type, and an exact record overrides its
parent wildcard — so a tool that silently drops wildcard-looking names discards
true findings where you cannot see it happen.

### Measured

A development benchmark resolves distinct names against a synthetic
authoritative zone on loopback. It is hermetic — not one packet leaves the
machine — so the number is reproducible on your hardware rather than a claim
you have to take on trust.

50 000 distinct names, 5 repetitions in randomized order, 20 ms of latency
added to every answer:

| client | q/s (median) | range | answered | correct |
|---|---:|---:|---:|---:|
| **subio** | **156 029** | 129 065 – 169 795 | 50 000 / 50 000 | 50 000 |
| go stdlib `net.Resolver` | 11 849 | 11 661 – 11 943 | 50 000 / 50 000 | 50 000 |

13.2x, with both clients answering every name and every answer verified
against the zone's deterministic address. A throughput figure without that
verification is worthless: a client can always be fast by dropping work.

`massdns`, `puredns` and `shuffledns` are GPL-3.0, which is why subio does not
bundle them.

The wire codec, against `golang.org/x/net/dns/dnsmessage` — what a
conventional Go DNS client uses:

| operation | subio | dnsmessage |
|---|---:|---:|
| build one query | **42 ns**, 0 alloc | 143 ns, 0 alloc |
| classify one response | **59 ns**, 0 alloc | 303 ns, 0 alloc |
| full per-name cycle | **101 ns**, 0 alloc | 506 ns, 0 alloc |

None of this is an internet throughput figure. Real throughput is bound by
your resolvers, your network and the target's nameservers, and the report says
so every time it prints.


## The zone's own signature settles a wildcard

Every subdomain tool decides wildcards by probing: ask for random labels, see
whether they answer, compare. A wildcard whose answers vary defeats all of them.

DNSSEC already carries the answer. RFC 4034's RRSIG states the label count the
signer signed over, and a wildcard is signed as `*.b.example.com` — three
labels, because the asterisk is not one. So an answer for `a.b.example.com`,
which has four, comes back signed over three. Fewer signed labels than the name
has is the zone saying, in a signature it made itself, that it synthesized this.

subio reads it, and the research behind this found no other tool that does
(the note). It runs before the probe
and settles the question outright on a signed zone; an unsigned one yields no
proof either way, so the probe still answers everything else. The ledger records
which test decided, as `rrsig: signed over N labels` or the control labels.

Asking for DNSSEC records costs response bytes, so it is tied to wildcard
detection: `-no-wildcard` turns off the question and the cost of answering it
together.
