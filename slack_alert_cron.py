#!/usr/bin/env python3
"""Cron wrapper: run the detector over the last day, post NEW findings to a Slack webhook.

Any cadence up to 24h works — the window overlaps between runs and already-alerted
findings are remembered in a state file, so a (user, IP, operator, source) alerts once.
A lock file prevents overlapping runs: a slot that finds the previous run still going
exits 1 and the next slot retries.

Credentials and SLACK_WEBHOOK_URL are read from .env next to this script
(real environment variables win over .env), so the crontab needs no env setup.
The healthcheck ping after && only fires on exit 0, i.e. a run that did all its work:

    */30 * * * * cd /home/esp/spur-saas-log-enrichment && /home/esp/venv/bin/python slack_alert_cron.py >> anomaly_cron.log 2>&1 && curl -fsS -m 10 https://vigil.example/api/ping/<id>

Replay an existing report instead of a live extraction (still posts and saves state):

    ./slack_alert_cron.py reports/anomaly_report_20260813.json

Preview without side effects (no Slack post, no Teamtailor notes, no state writes):

    ./slack_alert_cron.py --dry-run [reports/some_report.json]

State files (all mode 0600, flat sorted JSON lists):
    .slack_alert_state.json    "email|ip|operator|source" already posted to Slack
    .teamtailor_noted.json     "account:candidate_id" already flagged with the security note
    .teamtailor_ai_noted.json  "account:application_id" already given the AI-tool info note
    .slack_alert_watermark.json  start time of the last run that finished with no failures

Each run scans back to that watermark rather than a fixed 24h: every source re-fetching a
whole day every 30 minutes is 48x redundant, and Slack's access log is rate limited, so the
pages dominate the run. A run with any failure leaves the watermark alone, so the next run
re-covers its window; a long outage widens the window until it reaches the 24h ceiling.
"""

import argparse
import fcntl
import html
import ipaddress
import json
import re
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests

from anomaly_detector import load_env, teamtailor_keys

# Service identities that never alert. Only non-human accounts belong here, so the list can
# live in source; system@okta.com appears as the actor on Okta's own security.request.blocked.
WHITELIST = {'jirabot', 'system@okta.com'}
REPO = os.path.dirname(os.path.abspath(__file__))
REPORT = os.path.join(REPO, 'reports', 'cron_last_day.json')
DRY_RUN_REPORT = os.path.join(REPO, 'reports', 'cron_dry_run.json')
STATE = os.path.join(REPO, '.slack_alert_state.json')
NOTED = os.path.join(REPO, '.teamtailor_noted.json')
AI_NOTED = os.path.join(REPO, '.teamtailor_ai_noted.json')
LOCK = os.path.join(REPO, '.slack_alert_cron.lock')
WATERMARK = os.path.join(REPO, '.slack_alert_watermark.json')
# isProxy findings are a lower-signal stream, so they go to their own channel rather than
# diluting the DPRK alerts. Unset means hold them, never fall back to the main webhook.
PROXY_WEBHOOK_VAR = 'SLACK_WEBHOOK_URL_PROXY'
TT_API = 'https://api.teamtailor.com/v1'
TT_NOTE = ('<p>Security flag: identified as a possible DPRK (North Korean) IT worker.</p>'
           '<p>Do not progress or engage with this candidate.</p>'
           '<p>Contact Security (emil.stahl@team.blue) before any further contact.</p>')
# Appended to a note that goes out through the recruiter's account (Security has no user in that workspace),
# so recruiters do not read it as their colleague's own words.
RECRUITER_FOOTER = '<p><em>Automated note from team.blue Security (emil.stahl@team.blue).</em></p>'
# Referrer hostname substring -> AI job tool name. These get an info note only, no Slack alert.
AI_TOOLS = {'jackandjill': 'Jack & Jill', 'hirify': 'Hirify', 'jobright': 'Jobright', 'simplify': 'Simplify',
            'scale.jobs': 'Scale.jobs', 'perplexity': 'Perplexity', 'chatgpt': 'ChatGPT'}

WINDOW_HOURS = 24           # ceiling on the scan window, and the window when there is no watermark
WINDOW_OVERLAP_MIN = 15     # re-scan this far before the last success so nothing falls through the seam
WINDOW_MIN_HOURS = 0.25     # floor, for two runs in quick succession
DETECTOR_TIMEOUT = 25 * 60  # seconds; must finish inside the 30-minute cron period
SLACK_SECTION_MAX = 3000    # Block Kit: section text limit (400 if exceeded)
SLACK_MAX_BLOCKS = 50       # Block Kit: blocks per message
SLACK_LINE_MAX = 2900       # one finding line; leaves room for the group title in the same section
MAX_JOBS_SHOWN = 8          # job applications listed per Teamtailor candidate
# Okta outcomes that mean the request went through; anything else (FAILURE, DENY, CHALLENGE,
# ABANDONED, UNANSWERED) is worth showing next to the finding.
OKTA_OK_OUTCOMES = ('SUCCESS', 'ALLOW')

FAILURES = []  # non-fatal problems; a run that had any exits 1 after doing its work, so the healthcheck notices


def log(msg):
    """Timestamped progress line; flushed so cron logs keep stdout/stderr in order."""
    print(f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S%z')} {msg}", flush=True)


def warn(msg):
    print(msg, file=sys.stderr, flush=True)


def fail(msg):
    FAILURES.append(msg)
    warn(msg)


def load_json(path, default):
    """Load a state file; a corrupt or wrong-shaped one stops the run loudly rather than silently
    resetting the dedup memory (which would re-post every finding of the window)."""
    if not os.path.exists(path):
        return default
    with open(path) as f:
        try:
            data = json.load(f)
        except ValueError as e:
            sys.exit(f"{path} is not valid JSON ({e}); repair or move it away")
    if not isinstance(data, type(default)):
        sys.exit(f"{path} should hold a JSON {type(default).__name__}, found {type(data).__name__}; repair or move it away")
    return data


def save_json(path, data):
    """Atomic replace with mode 0600: a crash mid-write never leaves a truncated state file."""
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def acquire_lock():
    """Exclusive non-blocking lock so two cron slots can never post the same findings twice.

    Exits 1 (no healthcheck ping) if a previous run is still going; the next slot retries."""
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        warn("another slack_alert_cron run is still in progress; skipping this one")
        sys.exit(1)
    return fd


def release_lock(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def retry_delay(response, attempt, cap=60):
    """Seconds to wait before retrying. Slack sends Retry-After; Teamtailor documents
    X-Rate-Limit-Reset (seconds left in the 50-requests-per-10s bucket) instead."""
    for header in ('Retry-After', 'X-Rate-Limit-Reset'):
        value = (response.headers.get(header) or '').strip()
        if value.isdecimal():
            return min(cap, int(value))
    return min(cap, 2 ** attempt)


def window_hours(now):
    """Hours to scan: back to the last clean run, less an overlap, capped at WINDOW_HOURS.

    No watermark, a stale one, or one in the future (clock change) all fall back to the
    full ceiling, which is what the job did before watermarks existed."""
    mark = load_json(WATERMARK, {})
    raw = mark.get('last_success') if isinstance(mark, dict) else None
    try:
        last = parse_ts(raw) if raw else None
    except (TypeError, ValueError):
        warn(f"unparseable watermark {raw!r}; scanning the full {WINDOW_HOURS}h window")
        last = None
    if not last or last > now:
        return WINDOW_HOURS
    hours = (now - last).total_seconds() / 3600 + WINDOW_OVERLAP_MIN / 60
    return min(WINDOW_HOURS, max(WINDOW_MIN_HOURS, hours))


def window_label(hours):
    """'45m' / '3.5h' / '24h' for the message footer."""
    if hours < 1:
        return f"{round(hours * 60)}m"
    return f"{hours:.1f}".rstrip('0').rstrip('.') + 'h'


def proxy_finding(a):
    """True for a finding raised by Okta's isProxy verdict rather than a watchlist match."""
    return (a.get('enrichment') or {}).get('source') == 'okta_is_proxy'


def check_config(dry_run):
    """Fail on a missing webhook before any note is posted; warn about disabled features."""
    webhook = os.environ.get('SLACK_WEBHOOK_URL')
    if not webhook and not dry_run:
        warn("SLACK_WEBHOOK_URL is not set (env or .env); refusing to run")
        sys.exit(2)
    if (os.environ.get('OKTA_ALERT_ON_PROXY') or '').strip().lower() in ('1', 'true', 'yes') \
            and not os.environ.get(PROXY_WEBHOOK_VAR):
        warn(f"OKTA_ALERT_ON_PROXY is on but {PROXY_WEBHOOK_VAR} is not set; isProxy findings "
             f"will be held rather than posted to the main channel")
    if bool(os.environ.get('OKTA_ORG_URL')) != bool(os.environ.get('OKTA_API_TOKEN')):
        warn("only one of OKTA_ORG_URL / OKTA_API_TOKEN is set; the Okta System Log check is disabled")
    if teamtailor_keys() and not (os.environ.get('TEAMTAILOR_NOTE_USER_ID') or os.environ.get('TEAMTAILOR_NOTE_USER_EMAIL')
                                  or any(k.startswith('TEAMTAILOR_NOTE_USER_ID_') for k in os.environ)):
        warn("TEAMTAILOR_NOTE_USER_ID is not set (nor TEAMTAILOR_NOTE_USER_EMAIL): Teamtailor profile notes are disabled")
    return webhook


# --- Teamtailor -------------------------------------------------------------

def tt_key(account):
    return os.environ.get(f"TEAMTAILOR_API_KEY_{(account or '').upper()}")


def tt_headers(key):
    return {'Authorization': f'Token token={key}', 'X-Api-Version': '20240904',
            'Accept': 'application/vnd.api+json', 'Content-Type': 'application/vnd.api+json'}


_tt_sessions = {}


def tt_session(account):
    """One keep-alive session per account (TLS handshake once, not once per request); None if no key."""
    key = tt_key(account)
    if not key:
        return None
    s = _tt_sessions.get(account)
    if s is None:
        s = requests.Session()
        s.headers.update(tt_headers(key))
        _tt_sessions[account] = s
    return s


def tt_request(session, method, url, retries=3, timeout_retries=2, **kw):
    """One Teamtailor call. Retries 429 (honouring X-Rate-Limit-Reset/Retry-After) and, for
    GET only, 5xx and a stalled request.

    POSTs are not retried on 5xx or a read timeout: the note may already have been created,
    and a missed note is retried on the next run anyway (it is not in the noted set). A
    ConnectionError never reached the server, so it is safe to repeat for any method."""
    kw.setdefault('timeout', 15)
    retried = timeouts = 0
    while True:
        try:
            r = session.request(method, url, **kw)
        except (requests.Timeout, requests.ConnectionError) as e:
            # ConnectTimeout subclasses both, and like any ConnectionError never delivered.
            safe = isinstance(e, requests.ConnectionError) or method == 'GET'
            timeouts += 1
            if not safe or timeouts > timeout_retries:
                raise
            time.sleep(2 ** (timeouts - 1))
            continue
        transient = r.status_code == 429 or (method == 'GET' and r.status_code >= 500)
        if transient and retried < retries:
            time.sleep(retry_delay(r, retried))
            retried += 1
            continue
        r.raise_for_status()
        return r


_note_users = {}  # account -> user id found by email (or None), looked up once per run


def note_user_id(account):
    """Author for notes in `account`. Teamtailor user ids are per workspace (the global id is a 404
    in every other workspace, verified 2026-09-25), so: TEAMTAILOR_NOTE_USER_ID_<WORKSPACE> if set,
    else the workspace user whose email is TEAMTAILOR_NOTE_USER_EMAIL, else TEAMTAILOR_NOTE_USER_ID
    as-is. None (after one warning) when the email matches nobody there: the callers then fall back
    to the recruiter (job owner) of the candidate's application, or skip the note."""
    ws = (account or '').upper()
    uid = os.environ.get(f"TEAMTAILOR_NOTE_USER_ID_{ws}")
    email = os.environ.get('TEAMTAILOR_NOTE_USER_EMAIL')
    if uid or not email:
        return uid or os.environ.get('TEAMTAILOR_NOTE_USER_ID')
    if account in _note_users:
        return _note_users[account]
    session = tt_session(account)
    if session is None:
        return None
    try:
        data = tt_request(session, 'GET', f"{TT_API}/users",
                          params={'filter[email]': email, 'page[size]': 1}).json().get('data') or []
    except Exception as e:
        warn(f"teamtailor note user lookup failed for {account}: {e}")  # not cached: retried on the next note
        return None
    uid = (data[0].get('id') if data else None) or None
    if not uid:
        warn(f"no Teamtailor user {email} in workspace {account}: notes there are posted as the job's recruiter "
             f"(add the user to that workspace or set TEAMTAILOR_NOTE_USER_ID_{ws} to change that)")
    _note_users[account] = uid
    return uid


def add_teamtailor_emails(new):
    """Audit events carry no email or job; look up email (unless the referrer scan already had it)
    plus each application's job and recruiter (job owner) for the (few) new Teamtailor findings."""
    for a in new:
        if a.get('source') != 'teamtailor' or not a.get('candidate_id'):
            continue
        s = tt_session(a.get('account'))
        if not s:
            continue
        base = f"{TT_API}/candidates/{a['candidate_id']}"
        if not a.get('candidate_email'):
            try:
                a['candidate_email'] = tt_request(s, 'GET', base).json()['data']['attributes'].get('email')
            except Exception as e:
                warn(f"teamtailor email lookup failed for {a['candidate_id']}: {e}")
        try:
            d = tt_request(s, 'GET', f"{base}/job-applications", params={'include': 'job.user'}).json()
            inc = {(i['type'], i['id']): i for i in d.get('included', [])}
            jobs = []
            for ja in d.get('data', []):
                rel = ja.get('relationships') or {}
                job = inc.get(('jobs', ((rel.get('job') or {}).get('data') or {}).get('id')))
                if not job:
                    continue
                owner = (((job.get('relationships') or {}).get('user') or {}).get('data') or {}).get('id')
                user = inc.get(('users', owner))
                ua = (user or {}).get('attributes') or {}
                # an invited user who never completed their profile has no name: show the email instead
                jobs.append((job['attributes'].get('title'), ua.get('name') or ua.get('email')))
                if user and not a.get('tt_recruiter_id'):
                    a['tt_recruiter_id'] = owner  # note author of last resort, see note_user_id
            a['tt_jobs'] = jobs
        except Exception as e:
            warn(f"teamtailor job lookup failed for {a['candidate_id']}: {e}")


def host_of(value):
    """Hostname of a referrer value, whether it is a URL, a host[:port] or a bare word; None if unparseable."""
    if not value:
        return None
    try:
        return urlparse(value if '//' in value else f'//{value}').hostname
    except ValueError:  # e.g. an unbalanced '[' in an applicant-supplied Referer
        return None


def bare_ip(value):
    """The IP if value (a referring site or URL) is a bare IP address, else None.

    Accepts '89.167.50.51', '127.0.0.1:8765', 'http://127.0.0.1:8765/', '[::1]:80' and '::1'."""
    for host in (value, host_of(value)):
        try:
            return str(ipaddress.ip_address((host or '').strip()))
        except ValueError:
            pass
    return None


def ai_tool(*values):
    """The AI job tool named in a referring site/URL hostname, else None.

    Only the hostname is matched, so a LinkedIn post URL mentioning 'simplify' in its path is not a hit."""
    hosts = ' '.join(host_of(v) or '' for v in values).lower()
    return next((name for token, name in AI_TOOLS.items() if token in hosts), None)


def parse_ts(value):
    """Teamtailor timestamps are ISO 8601 with offset; treat a naive one as UTC rather than crash."""
    ts = datetime.fromisoformat(value)
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


class _AccountError(Exception):
    """Raised inside the per-application loop for a problem that concerns the whole account."""


def referrer_findings(hours=WINDOW_HOURS):
    """Scan applications of the last `hours`; return (bare_ip_findings, ai_applications).

    Real job boards refer from a hostname; an IP referrer was the only link between the
    9 fake 'Tallinn' applicants of Sep 2026 (89.167.50.51, an 'Autobid' auto-apply app),
    7 of whom came from an IP no watchlist knew. AI-tool referrals are only noted.
    """
    from extractors.teamtailor_extractor import TeamtailorExtractor
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    found, ai = [], []
    for account, key in teamtailor_keys().items():
        try:
            tt = TeamtailorExtractor(key, account)
            company = None  # fetched only when a finding needs it for the profile URL
            url = f"{tt.BASE_URL}/job-applications"
            # 30 = API max page size; sparse fieldsets drop the job-ad HTML and cover letters (~20x smaller pages)
            # fields[job-applications] MUST name the relationships too: Teamtailor strips them otherwise (verified 2026-09-24)
            params = {'sort': '-created-at', 'page[size]': 30, 'include': 'candidate,job',
                      'fields[job-applications]': 'created-at,referring-site,referring-url,candidate,job',
                      'fields[candidates]': 'first-name,last-name,email', 'fields[jobs]': 'title'}
            rows = linked = 0
            while url:
                data = tt._get(url, params)
                params = None  # next links already carry the query
                included = data.get('included') or []
                cands = {i['id']: i.get('attributes') or {} for i in included if i.get('type') == 'candidates'}
                titles = {i['id']: (i.get('attributes') or {}).get('title') for i in included if i.get('type') == 'jobs'}
                for ja in data.get('data') or []:
                    try:
                        a = ja.get('attributes') or {}
                        if not a.get('created-at'):
                            continue
                        if parse_ts(a['created-at']) < cutoff:
                            url = None
                            break
                        rel = ja.get('relationships') or {}
                        cid = ((rel.get('candidate') or {}).get('data') or {}).get('id')
                        rows += 1
                        linked += bool(cid)
                        cand = cands.get(cid) or {}
                        name = f"{cand.get('first-name') or ''} {cand.get('last-name') or ''}".strip() or 'Unknown'
                        ip = bare_ip(a.get('referring-site')) or bare_ip(a.get('referring-url'))
                        local = bool(ip) and not ipaddress.ip_address(ip).is_global  # 127.0.0.1:8765 etc = candidate's own tool
                        if ip and cid and not local:
                            if company is None:
                                try:
                                    company = f"{tt._get(f'{tt.BASE_URL}/company')['data']['id']}@eu"
                                except Exception as e:
                                    raise _AccountError(f"company lookup failed: {e}") from e
                            found.append({'user': name, 'email': f"tt:{account}:{cid}", 'candidate_id': cid,
                                          'account': account, 'company': company, 'candidate_email': cand.get('email'),
                                          'ip': ip, 'vpn_operator': 'BARE_IP_REFERRER', 'source': 'teamtailor'})
                        tool = ai_tool(a.get('referring-site'), a.get('referring-url'))
                        tool = f"the AI job tool {tool}" if tool else (
                            f"a local tool at {a.get('referring-url') or ip}" if local else None)
                        if tool and cid:
                            ai.append({'account': account, 'application_id': ja['id'], 'candidate_id': cid,
                                       'user': name, 'tool': tool,
                                       'job': titles.get(((rel.get('job') or {}).get('data') or {}).get('id'))})
                    except _AccountError:
                        raise
                    except Exception as e:  # one odd row must not blind the rest of the window
                        warn(f"teamtailor referrer check skipped application {ja.get('id')} for {account}: {e}")
                else:
                    nxt = (data.get('links') or {}).get('next')
                    if nxt and not nxt.startswith(f"{tt.BASE_URL}/"):  # never send the token elsewhere
                        fail(f"teamtailor referrer check for {account}: ignoring off-host next link {nxt[:80]!r}")
                        nxt = None
                    url = nxt
            if rows and not linked:
                fail(f"teamtailor referrer check for {account}: {rows} applications but none linked to a candidate (API change?)")
            log(f"referrer scan {account}: {rows} applications, {linked} with candidate, "
                f"{sum(f['account'] == account for f in found)} bare-IP, {sum(a['account'] == account for a in ai)} tool notes")
        except Exception as e:
            fail(f"teamtailor referrer check failed for {account}: {e}")
    return found, ai


def note_text(note_html):
    """Visible text of a note, whitespace-normalised: Teamtailor rewrites the HTML it stores (e.g. wraps
    an address in a mailto anchor), so block tags become a space and inline tags vanish."""
    text = re.sub(r'</?(?:p|br|div|li|ul|ol|h\d)\b[^>]*>', ' ', note_html or '')
    return ' '.join(html.unescape(re.sub(r'<[^>]+>', '', text)).split())


def profile_has_note(account, candidate_id, note_html):
    """True if a note with the same visible text is already on the profile.

    The local noted sets miss notes posted before a state reset, from another host, or on a
    candidate later merged into this one, so the profile is checked before every post. A failed
    lookup returns False: a duplicate note beats a missing flag."""
    try:
        d = tt_request(tt_session(account), 'GET', f"{TT_API}/candidates/{candidate_id}/activities",
                       params={'filter[code]': 'note', 'page[size]': 30, 'sort': '-created-at'}).json()
    except Exception as e:
        warn(f"teamtailor note check failed for {account}:{candidate_id}: {e}")
        return False
    want = note_text(note_html)  # a stored note may carry RECRUITER_FOOTER after the body
    acts = d.get('data') if isinstance(d, dict) else None
    for act in acts if isinstance(acts, list) else []:
        try:  # the activity's data attribute is a JSON string: {"note": "<p>...</p>"}
            existing = json.loads((act.get('attributes') or {}).get('data') or '{}').get('note')
        except (ValueError, AttributeError):
            continue
        if existing and note_text(existing).startswith(want):
            return True
    return False


def post_note(account, candidate_id, user_id, note_html, as_recruiter=False):
    if as_recruiter:
        note_html += RECRUITER_FOOTER
    body = {'data': {'type': 'notes', 'attributes': {'note': note_html}, 'relationships': {
        'candidate': {'data': {'type': 'candidates', 'id': candidate_id}},
        'user': {'data': {'type': 'users', 'id': user_id}}}}}
    tt_request(tt_session(account), 'POST', f"{TT_API}/notes", json=body)


def application_recruiter(account, application_id):
    """User id of the job owner (recruiter) of one application; None if unknown or on error."""
    try:
        d = tt_request(tt_session(account), 'GET', f"{TT_API}/job-applications/{application_id}",
                       params={'include': 'job.user', 'fields[jobs]': 'user', 'fields[users]': 'id'}).json()
        return next((i['id'] for i in d.get('included', []) if i.get('type') == 'users'), None)
    except Exception as e:
        warn(f"teamtailor recruiter lookup failed for {account}:{application_id}: {e}")
        return None


def post_ai_notes(ai, dry_run=False):
    """Info note (no Slack) on applications sent via an AI job tool or a local tool, once per application."""
    noted = set(load_json(AI_NOTED, []))
    for a in ai:
        nk = f"{a['account']}:{a['application_id']}"
        if nk in noted:
            continue
        user_id = note_user_id(a['account']) if tt_key(a['account']) else None
        as_recruiter = False
        if not user_id and tt_key(a['account']):
            user_id = application_recruiter(a['account'], a['application_id'])
            as_recruiter = bool(user_id)
        if not user_id:
            continue
        if dry_run:
            log(f"dry run: would note application {nk} ({printable(a['tool'])})")
            continue
        # job title and tool text are external input (the tool text can embed the candidate's referring URL)
        note = (f"<p>Info: the application for {html.escape(a['job'] or 'a job')} was submitted via "
                f"{html.escape(a['tool'])}.</p><p>Not a security flag.</p>")
        if profile_has_note(a['account'], a['candidate_id'], note):
            noted.add(nk)
            save_json(AI_NOTED, sorted(noted))
            continue
        try:
            post_note(a['account'], a['candidate_id'], user_id, note, as_recruiter)
        except Exception as e:
            warn(f"teamtailor AI note failed for {nk}: {e}")
            continue
        noted.add(nk)
        save_json(AI_NOTED, sorted(noted))  # per success, so a crash never repeats a note


def post_teamtailor_notes(new, dry_run=False):
    """Flag every Teamtailor hit with a profile note, once per candidate.

    The noted set is separate from Slack state and saved per success, so a failed
    Slack post or a crash never leads to a second note on the same profile.
    """
    noted = set(load_json(NOTED, []))
    for a in new:
        if a.get('source') != 'teamtailor':
            continue
        nk = f"{a.get('account')}:{a.get('candidate_id')}"
        if nk in noted:
            a['tt_note'] = 'already flagged'
            continue
        user_id = note_user_id(a.get('account')) if tt_key(a.get('account')) else None
        as_recruiter = False
        if not user_id and tt_key(a.get('account')) and a.get('tt_recruiter_id'):
            user_id, as_recruiter = a['tt_recruiter_id'], True
        if not user_id:
            a['tt_note'] = 'not flagged (no key/user configured)'
            continue
        if dry_run:
            a['tt_note'] = 'dry run, not flagged'
            continue
        if profile_has_note(a['account'], a['candidate_id'], TT_NOTE):
            noted.add(nk)
            a['tt_note'] = 'already flagged'
            save_json(NOTED, sorted(noted))
            continue
        try:
            post_note(a['account'], a['candidate_id'], user_id, TT_NOTE, as_recruiter)
        except Exception as e:
            warn(f"teamtailor note failed for {nk}: {e}")
            a['tt_note'] = 'note FAILED, flag manually'
            continue
        noted.add(nk)
        a['tt_note'] = 'profile flagged'
        save_json(NOTED, sorted(noted))


# --- findings ----------------------------------------------------------------

def whitelisted(a):
    """Internal Slack/Zoom/Okta identities only: a Teamtailor applicant chooses their own name."""
    return a.get('source') != 'teamtailor' and (a.get('user') in WHITELIST or a.get('email') in WHITELIST)


def finding_key(a):
    """email|ip|operator|source. The extractors emit the literal 'Unknown' for a missing email, so
    fall back to the display name: two anonymous Zoom guests on one watchlist IP must not share a key."""
    email = a.get('email')
    who = email if email and email != 'Unknown' else f"user:{a.get('user') or 'Unknown'}"
    return f"{who}|{a.get('ip')}|{a.get('vpn_operator')}|{a.get('source')}"


def legacy_key(a):
    return f"{a.get('email')}|{a.get('ip')}|{a.get('vpn_operator')}|{a.get('source')}"


def new_findings(anomalies, seen):
    """Return anomalies not yet alerted; mutates seen with their keys."""
    new = []
    for a in anomalies:
        key = finding_key(a)
        if key in seen or legacy_key(a) in seen:  # legacy: 'Unknown|...' keys written before the fallback
            continue
        seen.add(key)
        new.append(a)
    return new


# --- Slack -------------------------------------------------------------------

def mrkdwn(value):
    """Escape external text for Slack mrkdwn: & < > would otherwise be parsed as markup,
    and a candidate named '<!channel>' or '<https://x|y>' would ping the channel or inject a link."""
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def printable(text):
    """Strip control characters (newlines, ANSI escapes) from external text before it reaches a log line."""
    return ''.join(ch for ch in str(text) if ch.isprintable())


def clip(text, limit):
    return text if len(text) <= limit else text[:limit - 1] + '…'


def build_payload(new, hours=WINDOW_HOURS):
    """Slack Block Kit message: header, one or more sections per source, context footer."""
    def op_name(a):
        return mrkdwn((a.get('vpn_operator') or 'Unknown').replace('_', ' ').title())

    def who(a):
        user = clip(mrkdwn(a.get('user') or 'Unknown'), 200)
        email = a.get('email')
        return f"*{user}*" + (f" ({clip(mrkdwn(email), 200)})" if email and email != 'Unknown' else "")

    slack_lines = [
        f"• {who(a)} — {op_name(a)} — `{mrkdwn(a.get('ip'))}`"
        for a in new if a.get('source') == 'slack'
    ]
    zoom_lines = [
        f"• {who(a)} — {op_name(a)} — `{mrkdwn(a.get('ip'))}`"
        + (f" — _{mrkdwn(a['meeting_topic'])}_" if a.get('meeting_topic') else "")
        for a in new if a.get('source') == 'zoom'
    ]

    def tt_line(a):
        url = (f"https://app.teamtailor.com/companies/{a.get('company', '')}"
               f"/candidates/segment/all/candidate/{a.get('candidate_id')}")
        email = f" — `{clip(mrkdwn(a['candidate_email']), 200)}`" if a.get('candidate_email') else ""
        all_jobs = a.get('tt_jobs') or []
        jobs = "".join(f"\n    ↳ {clip(mrkdwn(title or 'untitled job'), 200)} — recruiter: *{clip(mrkdwn(rec or 'unknown'), 100)}*"
                       for title, rec in all_jobs[:MAX_JOBS_SHOWN])
        if len(all_jobs) > MAX_JOBS_SHOWN:  # auto-apply bots rack up dozens of applications
            jobs += f"\n    ↳ … and {len(all_jobs) - MAX_JOBS_SHOWN} more application(s)"
        return (f"• <{url}|{clip(mrkdwn(a.get('user') or 'Unknown'), 200)}>{email} — {op_name(a)} — `{mrkdwn(a.get('ip'))}` — "
                f"{mrkdwn(a.get('account'))} — _{mrkdwn(a.get('tt_note', ''))}_{jobs}")

    tt_lines = [tt_line(a) for a in new if a.get('source') == 'teamtailor']
    def okta_line(a):
        # Country and network carry most of the triage value: "Astrill from China" is a
        # different conversation from the same operator seen at a known office range.
        where = ' / '.join(x for x in (a.get('country'), a.get('as_org')) if x)
        return (f"• {who(a)} — {op_name(a)} — `{mrkdwn(a.get('ip'))}`"
                + (f" — {clip(mrkdwn(where), 120)}" if where else "")
                + (f" — _{mrkdwn(a['action'])}_" if a.get('action') else "")
                + (f" — *{mrkdwn(a['outcome'])}*"
                   if a.get('outcome') and a['outcome'] not in OKTA_OK_OUTCOMES else "")
                + (" — _okta: proxy_" if a.get('is_proxy') else ""))

    okta_lines = [okta_line(a) for a in new if a.get('source') == 'okta']
    other_lines = [  # safety net for a source the detector may grow later
        f"• {who(a)} — {op_name(a)} — `{mrkdwn(a.get('ip'))}` — {mrkdwn(a.get('source', '?'))}"
        for a in new if a.get('source') not in ('slack', 'zoom', 'teamtailor', 'okta')
    ]

    sections = []
    for title, lines in [("💬 *Slack logins*", slack_lines),
                         ("🎥 *Zoom meetings*", zoom_lines),
                         ("🧑‍💼 *Teamtailor applicants*", tt_lines),
                         ("🔐 *Okta sign-ins*", okta_lines),
                         ("❓ *Other*", other_lines)]:
        if not lines:
            continue
        chunk = title
        for line in lines:  # Slack rejects (400) section text over 3000 chars
            line = clip(line, SLACK_LINE_MAX)
            if len(chunk) + 1 + len(line) > SLACK_SECTION_MAX:
                sections.append(chunk)
                chunk = line
            else:
                chunk += '\n' + line
        sections.append(chunk)

    room = SLACK_MAX_BLOCKS - 2  # header + context footer
    if len(sections) > room:
        omitted = len(sections) - (room - 1)
        sections = sections[:room - 1] + [f"… {omitted} more section(s) omitted; see anomaly_cron.log and this run's report"]

    blocks = [{'type': 'header',
               'text': {'type': 'plain_text',
                        'text': f"🚨 {len(new)} new VPN/proxy detection{'s' if len(new) != 1 else ''}"}}]
    blocks += [{'type': 'section', 'text': {'type': 'mrkdwn', 'text': s}} for s in sections]
    blocks.append({'type': 'context', 'elements': [{
        'type': 'mrkdwn',
        'text': f"Last {window_label(hours)} window · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    }]})

    fallback = clip(f"{len(new)} new VPN/proxy detection(s): " + ", ".join(
        f"{mrkdwn(a.get('user') or a.get('email'))} via {op_name(a)}" for a in new), SLACK_SECTION_MAX)
    return {'text': fallback, 'blocks': blocks}


def post_slack(webhook, payload, retries=3):
    """Post to the incoming webhook. Retries 429/5xx and network errors with backoff.

    A 400 means Slack rejected the blocks; the plain-text fallback is posted instead so the
    alert still lands and state can be saved. Errors never quote the URL: it is the credential."""
    for attempt in range(retries + 1):
        try:
            r = requests.post(webhook, json=payload, timeout=10)
        except requests.ConnectionError as e:  # never delivered, safe to retry; a ReadTimeout is not (may have posted)
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
            raise RuntimeError(f"Slack webhook unreachable: {type(e).__name__}") from None
        except requests.RequestException as e:
            raise RuntimeError(f"Slack webhook request failed: {type(e).__name__}") from None
        if (r.status_code == 429 or r.status_code >= 500) and attempt < retries:
            time.sleep(retry_delay(r, attempt))
            continue
        if r.status_code == 400 and 'blocks' in payload:
            fail(f"Slack rejected the blocks ({r.text[:200]}); posting the plain-text fallback instead")
            return post_slack(webhook, {'text': payload['text']}, retries)
        if not r.ok:
            raise RuntimeError(f"Slack webhook returned {r.status_code}: {r.text[:300]}")
        return


# --- main --------------------------------------------------------------------

def tail(text, n=2000):
    if isinstance(text, bytes):
        text = text.decode(errors='replace')
    return (text or '')[-n:]


def run_detector(output=None, hours=WINDOW_HOURS):
    """Extract the window from every source and write the report. Returns the elapsed seconds.

    Exits 1 on failure or timeout. The detector deliberately exits 0 when one source fails
    (it prints the failure to stderr), so its stderr is forwarded and counted here."""
    cmd = [sys.executable, 'anomaly_detector.py', '--enrichment', 'file',
           '--ip-file', 'data.csv', '--hours', f"{hours:.4f}", '--output', output or REPORT]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=DETECTOR_TIMEOUT)
    except subprocess.TimeoutExpired as e:  # .stdout/.stderr are bytes here even with text=True
        warn(f"detector killed after {DETECTOR_TIMEOUT}s:\n{tail(e.stdout)}\n{tail(e.stderr)}")
        sys.exit(1)
    if proc.returncode:
        warn(f"detector failed (exit {proc.returncode}):\n{tail(proc.stdout)}\n{tail(proc.stderr)}")
        sys.exit(1)
    for line in proc.stderr.splitlines():
        if line.strip():
            (fail if 'failed' in line.lower() else warn)(f"detector: {line.rstrip()}")
    return time.monotonic() - t0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('report', nargs='?', help='replay this report instead of running the detector '
                                                  '(also skips the Teamtailor referrer scan)')
    parser.add_argument('--dry-run', action='store_true',
                        help='print what would happen; no Slack post, no Teamtailor notes, no state writes')
    args = parser.parse_args()

    load_env()
    webhook = check_config(args.dry_run)
    started = datetime.now(timezone.utc)  # the watermark, so events during the run are not skipped
    if args.dry_run and args.report:
        run(args, webhook, started)  # replaying a file touches nothing shared
    else:
        lock_fd = acquire_lock()  # a live dry run still runs the detector and the scan
        try:
            run(args, webhook, started)
        finally:
            release_lock(lock_fd)
    if not FAILURES and args.report is None and not args.dry_run:
        # Only a run that did all its work moves the mark; a failed one is re-covered next time.
        save_json(WATERMARK, {'last_success': started.isoformat()})
    if FAILURES:
        warn(f"{len(FAILURES)} non-fatal failure(s) this run (see above); exiting 1 so the healthcheck notices")
        sys.exit(1)


def run(args, webhook, started=None):
    live = args.report is None
    started = started or datetime.now(timezone.utc)
    hours = window_hours(started) if live else WINDOW_HOURS
    report_path = args.report or (DRY_RUN_REPORT if args.dry_run else REPORT)  # a preview never clobbers the cron's report
    elapsed = run_detector(report_path, hours) if live else None
    with open(report_path) as f:
        report = json.load(f)
    anomalies = report['anomalies']
    s = report.get('summary') or {}
    counts = ' '.join(f"{name} {s[key]}" for name, key in
                      (('slack', 'slack_entries'), ('zoom', 'zoom_entries'),
                       ('teamtailor', 'teamtailor_entries'), ('okta', 'okta_entries'))
                      if key in s)
    log((f"detector {elapsed:.0f}s window {window_label(hours)}" if live else f"report {args.report}")
        + f": {counts} anomalies {len(anomalies)}")
    if live:
        bare, ai = referrer_findings(hours)
        anomalies += bare
        post_ai_notes(ai, dry_run=args.dry_run)
    anomalies = [a for a in anomalies if not whitelisted(a)]

    seen = set(load_json(STATE, []))
    new = new_findings(anomalies, seen)

    if not new:
        log("no new findings")
        return

    add_teamtailor_emails(new)  # read-only lookups, fine in a dry run too
    post_teamtailor_notes(new, dry_run=args.dry_run)
    proxy_new = [a for a in new if proxy_finding(a)]
    main_new = [a for a in new if not proxy_finding(a)]

    if args.dry_run:
        log(f"dry run: {len(new)} new finding(s) ({len(main_new)} main, {len(proxy_new)} isProxy); "
            f"payloads follow (nothing posted, state untouched)")
        for label, group in (('main', main_new), ('isProxy', proxy_new)):
            if group:
                print(f"--- {label} ---", flush=True)
                print(json.dumps(build_payload(group, hours), indent=2, ensure_ascii=False), flush=True)
        return

    if main_new:
        post_slack(webhook, build_payload(main_new, hours))
        log(f"posted {len(main_new)} new finding(s) to Slack")
    if proxy_new:
        proxy_webhook = os.environ.get(PROXY_WEBHOOK_VAR)
        if proxy_webhook:
            post_slack(proxy_webhook, build_payload(proxy_new, hours))
            log(f"posted {len(proxy_new)} new isProxy finding(s) to the proxy channel")
        else:
            # Hold rather than misroute: drop their keys so they post once the hook exists.
            fail(f"{PROXY_WEBHOOK_VAR} is not set; holding {len(proxy_new)} isProxy finding(s)")
            for a in proxy_new:
                seen.discard(finding_key(a))

    # Save state only after a successful post, so failures retry next run.
    # ponytail: entries carry no date, so the file grows forever (a few entries/day) and a
    # recurring user+IP+operator alerts exactly once; re-alerting would need a {key: last_seen} dict.
    save_json(STATE, sorted(seen))


if __name__ == '__main__':
    main()
