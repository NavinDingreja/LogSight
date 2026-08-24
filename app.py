#!/usr/bin/env python3
"""
LogSight — Enterprise Log Analyzer (simple form-post version, no JS fetch)
Run: python app.py   ->  http://127.0.0.1:5000
"""

import json
import re
from collections import Counter
from datetime import datetime

from flask import Flask, render_template, request

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

CLF_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

ISO_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)Z?\s*'
    r'\[?(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)?\]?\s*[:\-]?\s*(?P<msg>.*)$',
    re.IGNORECASE
)

SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^:\[]+)(?:\[\d+\])?:\s*(?P<msg>.*)$'
)

IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

MONTHS = {m: i + 1 for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'])}

ERROR_KEYWORDS = re.compile(r'\b(error|exception|fail(?:ed|ure)?|fatal|critical)\b', re.IGNORECASE)
WARN_KEYWORDS = re.compile(r'\b(warn(?:ing)?|deprecat(?:ed|ion)|retry(?:ing)?)\b', re.IGNORECASE)
DEBUG_KEYWORDS = re.compile(r'\b(debug|trace)\b', re.IGNORECASE)


def normalize_level(raw):
    if not raw:
        return None
    raw = raw.upper()
    if raw == 'WARNING':
        return 'WARN'
    if raw in ('CRITICAL', 'FATAL'):
        return 'ERROR'
    if raw == 'TRACE':
        return 'DEBUG'
    return raw


def level_from_status(status):
    try:
        n = int(status)
    except ValueError:
        return 'INFO'
    if n >= 500:
        return 'ERROR'
    if n >= 400:
        return 'WARN'
    return 'INFO'


def level_from_keywords(line):
    if ERROR_KEYWORDS.search(line):
        return 'ERROR'
    if WARN_KEYWORDS.search(line):
        return 'WARN'
    if DEBUG_KEYWORDS.search(line):
        return 'DEBUG'
    return 'INFO'


def parse_clf_date(ts):
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})', ts)
    if not m:
        return None
    day, mon, year, hh, mm, ss = m.groups()
    try:
        return datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except (KeyError, ValueError):
        return None


def parse_iso_date(ts):
    ts = ts.replace(',', '.').replace('T', ' ')
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def parse_syslog_date(ts):
    try:
        return datetime.strptime(f'{ts} {datetime.now().year}', '%b %d %H:%M:%S %Y')
    except ValueError:
        return None


def parse_line(line, source):
    line = line.rstrip('\n').rstrip('\r')
    if not line.strip():
        return None

    m = CLF_RE.match(line)
    if m:
        d = m.groupdict()
        size = int(d['size']) if d['size'].isdigit() else 0
        ts = parse_clf_date(d['ts'])
        return {
            'source': source, 'ip': d['ip'],
            'timestamp': ts.isoformat() if ts else None,
            'ts_epoch': ts.timestamp() if ts else None,
            'level': level_from_status(d['status']),
            'method': d['method'], 'path': d['path'], 'status': d['status'], 'size': size,
            'message': f"{d['method']} {d['path']} \u2192 {d['status']}"
        }

    m = ISO_RE.match(line)
    if m and m.group('ts'):
        d = m.groupdict()
        ip_match = IP_RE.search(line)
        ts = parse_iso_date(d['ts'])
        return {
            'source': source, 'ip': ip_match.group(1) if ip_match else None,
            'timestamp': ts.isoformat() if ts else None,
            'ts_epoch': ts.timestamp() if ts else None,
            'level': normalize_level(d['level']) or level_from_keywords(d['msg'] or line),
            'method': None, 'path': None, 'status': None, 'size': 0,
            'message': (d['msg'] or line).strip()
        }

    m = SYSLOG_RE.match(line)
    if m:
        d = m.groupdict()
        ip_match = IP_RE.search(line)
        ts = parse_syslog_date(d['ts'])
        return {
            'source': source, 'ip': ip_match.group(1) if ip_match else None,
            'timestamp': ts.isoformat() if ts else None,
            'ts_epoch': ts.timestamp() if ts else None,
            'level': level_from_keywords(d['msg']),
            'method': None, 'path': None, 'status': None, 'size': 0,
            'message': f"{d['proc'].strip()}: {d['msg']}"
        }

    ip_match = IP_RE.search(line)
    return {
        'source': source, 'ip': ip_match.group(1) if ip_match else None,
        'timestamp': None, 'ts_epoch': None,
        'level': level_from_keywords(line),
        'method': None, 'path': None, 'status': None, 'size': 0,
        'message': line.strip()
    }


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def build_stats(entries):
    level_counts = Counter(e['level'] for e in entries)
    ip_counts = Counter(e['ip'] for e in entries if e['ip'])
    status_counts = Counter(f"{e['status'][0]}xx" for e in entries if e['status'])

    error_sigs = Counter()
    for e in entries:
        if e['level'] == 'ERROR':
            sig = re.sub(r'\d+', '#', e['message'])[:80]
            error_sigs[sig] += 1

    with_time = [e for e in entries if e['ts_epoch'] is not None]
    time_range = None
    buckets = []
    if with_time:
        epochs = sorted(e['ts_epoch'] for e in with_time)
        start, end = epochs[0], epochs[-1]
        time_range = {'start': datetime.fromtimestamp(start).strftime('%b %d, %H:%M'),
                       'end': datetime.fromtimestamp(end).strftime('%b %d, %H:%M')}
        span = (end - start) or 1
        bucket_count = 24
        bucket_secs = max(span / bucket_count, 1)
        buckets = [{'label': datetime.fromtimestamp(start + i * bucket_secs).strftime('%H:%M'),
                    'ERROR': 0, 'WARN': 0, 'INFO': 0, 'DEBUG': 0} for i in range(bucket_count)]
        for e in with_time:
            idx = int((e['ts_epoch'] - start) / bucket_secs)
            idx = min(max(idx, 0), bucket_count - 1)
            lvl = e['level']
            if lvl in buckets[idx]:
                buckets[idx][lvl] += 1

    total = len(entries)
    error_rate = round((level_counts.get('ERROR', 0) / total) * 100, 2) if total else 0.0
    span_label = None
    if time_range:
        mins = span / 60
        span_label = f"{mins:.0f} min" if mins < 60 else (
            f"{mins/60:.1f} hrs" if mins < 2880 else f"{mins/1440:.1f} days")

    return {
        'total': total,
        'level_counts': dict(level_counts),
        'top_ips': ip_counts.most_common(10),
        'status_counts': dict(status_counts),
        'top_errors': error_sigs.most_common(10),
        'time_range': time_range,
        'span_label': span_label,
        'buckets': buckets,
        'error_rate': error_rate,
        'unique_ips': len(ip_counts),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def upload():
    return render_template('upload.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    files = request.files.getlist('files')
    files = [f for f in files if f and f.filename]

    if not files:
        return render_template('upload.html', error="No files selected. Please choose at least one log file.")

    entries = []
    filenames = []
    for f in files:
        filenames.append(f.filename)
        raw = f.read().decode('utf-8', errors='replace')
        for line in raw.splitlines():
            parsed = parse_line(line, f.filename)
            if parsed:
                entries.append(parsed)

    if not entries:
        return render_template('upload.html', error="No readable log lines were found in the uploaded file(s).")

    stats = build_stats(entries)

    # Cap rows shown in the explorer table to keep the report page light
    MAX_ROWS = 2000
    table_rows = entries[:MAX_ROWS]

    return render_template(
        'report.html',
        generated_at=datetime.now().strftime('%B %d, %Y at %H:%M'),
        filenames=filenames,
        stats=stats,
        entries=table_rows,
        total_entries=len(entries),
        shown_entries=len(table_rows),
        buckets_json=json.dumps(stats['buckets']),
        level_counts_json=json.dumps(stats['level_counts']),
        status_counts_json=json.dumps(stats['status_counts']),
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)