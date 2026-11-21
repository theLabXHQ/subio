# NSEC3 posture

[← back to the README](../README.md)

## Deciding whether a zone is worth walking

An NSEC3 ring can list a whole zone with no guessing, or be the most expensive
thing a run does. `subio nsec3` says which, from three queries for names that
cannot exist — what any resolver sends on a typo. It reads no name from the zone
and it is not a walk.

```
subio nsec3 -d example.com
subio nsec3 -l zones.txt -rs 9.9.9.9 -j
```

```
ZONE            DENIAL            HASH   ITER  OPT-OUT  WALKABLE
nic.cz          nsec3             SHA-1  0     no       yes
com             nsec3             SHA-1  0     yes      no
cloudflare.com  nsec-synthesized  -      -     -        no
```

Five things can deny a name's absence and they are not interchangeable:

| `DENIAL` | What it means for a walk |
|---|---|
| `nsec3`, no opt-out | the ring can be closed, which is a **complete list** of the zone |
| `nsec3`, opt-out | a gap never proves absence, so the ring never closes |
| `nsec` | easier than NSEC3: each record names its successor in plain text |
| `nsec-synthesized` | **black lies**: the record is generated per query, so a walk returns nothing |
| `none` / `no-answer` | unsigned, or DNSSEC not returned by this resolver — different facts, kept apart |

That fourth row is why the check exists. A black-lies zone is signed, validates,
and looks like the easiest possible target; walking it only makes traffic. The
test is that the probe invents a random label and no record in a real zone can
mention a label invented a moment ago.

Measured across 64 real zones: 33 of 36
NSEC3 zones use **zero** iterations, so the per-guess hash cost the design notes
worried about is not a real constraint. Opt-out splits by level — 21 of 27 TLDs
set it against 3 of 9 second-level zones — so the stage is aimed at the half of
the problem where it is the exception. Six of fourteen NSEC zones in the sample
served black lies. About half the second-level zones measured can be enumerated
completely with no guessing.
