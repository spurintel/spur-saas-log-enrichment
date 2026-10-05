# Bug report: intermittent read timeouts on GET /v1/audit-events

**To:** support@teamtailor.com
**From:** team.blue Security (emil.stahl@team.blue)
**Date:** 2026-09-28
**Severity:** low frequency, high impact — each occurrence silently drops a workspace from a
security scan

## Summary

Since 2026-09-25 the EU API host `api.teamtailor.com` intermittently accepts a request and then
never sends a response body. The connection is established and no status line arrives within
30 seconds, so the client aborts with a read timeout. It is not a 429 and not a 5xx: nothing
comes back at all.

The failures cluster in time across *different* workspaces and *different* API keys, which is
what makes us think it is server side rather than anything specific to one account.

## What we run

A read-only security job polls the audit log of 37 Teamtailor workspaces every 30 minutes,
looking for applicant IP addresses that match a threat-intel watchlist. Per workspace, per run:

```
GET https://api.teamtailor.com/v1/company
GET https://api.teamtailor.com/v1/audit-events?sort=-id&page[size]=30
    (then follow links.next until the 24h cutoff — typically 1–3 pages)
Authorization: Token token=<per-workspace key>
X-Api-Version: 20240904
Accept: application/vnd.api+json
```

That is roughly 2–5 requests per workspace per run, each workspace on its own API key. Well
inside the documented bucket of 50 requests per 10 seconds, and `page[size]=30` is the
documented maximum. We have never seen a 429 from this job.

## Occurrences

184 runs logged between 2026-09-24 18:30 and 2026-09-28 16:30 CEST. 6 of them (3.3%) hit at
least one timeout, 13 workspace fetches in total:

| Run (UTC) | Run (CEST) | Workspaces that timed out |
|---|---|---|
| 2026-09-25 01:30 | 03:30 | global |
| 2026-09-28 11:00 | 13:00 | global, ticimax, windsor, iubenda |
| 2026-09-28 11:30 | 13:30 | global |
| 2026-09-28 12:00 | 14:00 | accessiway, global, iubenda |
| 2026-09-28 14:00 | 16:00 | global, accessiway |
| 2026-09-28 14:30 | 16:30 | accessiway, global |

Per workspace: global 6, accessiway 3, iubenda 2, ticimax 1, windsor 1.

The three runs from 11:00 to 12:00 UTC and the two from 14:00 to 14:30 UTC are consecutive,
so the condition appears to persist for roughly an hour at a time rather than being a single
slow request.

Client-side error, identical every time:

```
HTTPSConnectionPool(host='api.teamtailor.com', port=443):
Read timed out. (read timeout=30)
```

Requests are issued from an EU host (Denmark) over a persistent HTTPS session with connection
reuse, one session per workspace.

## What we have ruled out

- **Rate limiting** — no 429 was returned, and our request rate is far below 50 per 10 seconds.
  A 429 with `X-Rate-Limit-Reset` would have been retried; nothing arrived to retry.
- **A single bad workspace or key** — five different workspaces on five different keys failed,
  and the same keys succeed on the runs immediately before and after.
- **Large payloads** — `page[size]` is 30, the documented maximum, and the window is 24 hours,
  so the pages are small (a few hundred events across all 37 workspaces per run).
- **Our network** — Slack, Zoom and Spur calls from the same host, in the same process, in the
  same runs, all completed normally.

## Impact

A timeout aborts that workspace's extraction for the run, so its audit events are not scanned
in that window. In our case that means a possible detection is delayed by up to 30 minutes.
The next clean run re-covers the window, so nothing is lost permanently — but until we patched
our client today, each occurrence also failed the job's health check and paged an on-call
engineer. Five pages in one afternoon.

## What we would like to know

1. Is there a known incident or capacity issue on the EU API host covering
   2026-09-28 11:00–14:30 UTC?
2. Is `/v1/audit-events` with `sort=-id` expected to be slow for some workspaces? Would a
   `filter[...]` on the timestamp be cheaper server side than sorting and paging from the newest
   event until we reach our own cutoff? We would happily switch if there is a documented filter
   for that endpoint.
3. We cannot give you an `x-request-id` for the failures: a stalled request returns no
   response and therefore no headers, and at the time we were not recording the ids of the
   *successful* calls either. We have since changed the client to remember the last answered
   `x-request-id` per workspace session and to quote it when the next request stalls, so from
   now on we can hand you the id of the call immediately preceding each timeout. Tell us if
   there is something more useful to capture — we can add response headers, timing, or a
   packet capture.
4. Is there a recommended client timeout for this endpoint? We use 30 seconds; if p99 is
   genuinely higher than that, we would rather raise ours than retry.

## Workaround on our side

As of 2026-09-28 our client retries a stalled request twice with backoff before giving up, so
a single slow response no longer drops a whole workspace. We would still like the underlying
behaviour understood, since the retries are papering over lost responses rather than slow ones.

Happy to provide workspace IDs, exact timestamps or a packet capture on request.
