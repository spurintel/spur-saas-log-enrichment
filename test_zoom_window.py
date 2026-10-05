"""Offline self-check for the Zoom meeting-window filter.

The Dashboard API lists meetings by whole date, so a sub-day window must be applied client
side before the per-meeting participant calls, which are what make the extractor slow.

Run: python test_zoom_window.py
"""

from datetime import datetime, timedelta, timezone

from extractors.zoom_extractor import ZoomExtractor, parse_zoom_ts

NOW = datetime(2026, 9, 28, 17, 0, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=45)


def m(start=None, end=None):
    out = {}
    if start:
        out['start_time'] = start
    if end:
        out['end_time'] = end
    return out


def test_window_filter():
    keep = ZoomExtractor._overlaps
    # squarely inside
    assert keep(m('2026-09-28T16:20:00Z', '2026-09-28T16:50:00Z'), START, NOW)
    # started before the window but still running when it opened: a late joiner counts
    assert keep(m('2026-09-28T09:00:00Z', '2026-09-28T16:30:00Z'), START, NOW)
    # a call still in progress, no end_time yet
    assert keep(m('2026-09-28T16:00:00Z'), START, NOW)
    # finished before the window opened
    assert not keep(m('2026-09-28T08:00:00Z', '2026-09-28T09:00:00Z'), START, NOW)
    # earlier the same calendar day, which is exactly what the date-granularity API returns
    assert not keep(m('2026-09-28T00:30:00Z', '2026-09-28T01:15:00Z'), START, NOW)
    # starts after the window closes
    assert not keep(m('2026-09-28T18:00:00Z', '2026-09-28T18:30:00Z'), START, NOW)
    # no timestamps at all: keep it, a wasted request beats a missed IP
    assert keep(m(), START, NOW)
    # unparseable timestamps degrade to keeping it
    assert keep(m('not a date', 'nor this'), START, NOW)
    print('zoom window filter ok')


def test_a_full_day_window_keeps_the_day():
    keep = ZoomExtractor._overlaps
    day_start = NOW - timedelta(days=1)
    for meeting in (m('2026-09-28T00:30:00Z', '2026-09-28T01:15:00Z'),
                    m('2026-09-28T16:20:00Z', '2026-09-28T16:50:00Z'),
                    m('2026-09-27T23:00:00Z', '2026-09-28T00:10:00Z')):
        assert keep(meeting, day_start, NOW), meeting
    print('24h window unchanged ok')


def test_parse():
    assert parse_zoom_ts('2026-09-28T16:20:00Z') == datetime(2026, 9, 28, 16, 20, tzinfo=timezone.utc)
    assert parse_zoom_ts('2026-09-28T16:20:00') == datetime(2026, 9, 28, 16, 20, tzinfo=timezone.utc)
    assert parse_zoom_ts(None) is None and parse_zoom_ts('') is None and parse_zoom_ts('x') is None
    print('zoom timestamp parsing ok')


if __name__ == '__main__':
    test_window_filter()
    test_a_full_day_window_keeps_the_day()
    test_parse()
