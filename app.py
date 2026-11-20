"""SentinelSOC · Local analyst workbench (v3).  python -m streamlit run app.py

Live mode uses Wazuh Indexer API over a separately established SSH tunnel.
No Wazuh credentials are included in the project.
"""
from collections import Counter
from hashlib import sha256
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))


import numpy as np
import numpy.ma
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from workbench.engine import load_jsonl, group_cases, markdown_case_report, normalize_alert
from workbench.state import connect, get_review, save_review, review_history
from workbench.live import fetch_recent_alerts, LiveSourceError
from workbench.refresh import should_fetch_live
from workbench.correlation import build_timelines, timeline_report
from workbench.attack_mapping import map_alerts, attack_report_section
from workbench.response import response_report_section
from workbench.escalation import sync_escalations, list_escalations
from workbench.response_ui import render_case_recommendations, render_escalation_inbox
from workbench.notifications_ui import render_notification_handoffs

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "sentinelsoc-alerts.jsonl"
DB = ROOT / "local" / "triage.sqlite3"

COLORS = {
    "cyan": "#39DFD1", "violet": "#9390FF", "amber": "#FFBD75",
    "red": "#FF6D82", "blue": "#5DADFF", "muted": "#92A9C4",
    "base": "#0A1120", "panel": "#121F34", "outline": "#263952",
}

st.set_page_config(page_title="SentinelSOC | Security Operations", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

STYLES = """
<style>
:root { color-scheme: dark; }
.stApp {
  background: radial-gradient(ellipse at 76% 3%, rgba(64,81,190,.16), transparent 33%),
              radial-gradient(ellipse at 12% 18%, rgba(16,184,166,.085), transparent 30%),
              #080F1D;
  color:#E7F1FD;
}
.block-container {padding-top: 1.7rem; padding-bottom: 3rem; max-width: 1500px;}
[data-testid="stSidebar"] { background: #0C1729; border-right: 1px solid #26334B; }
[data-testid="stSidebar"] .block-container {padding-top: 2rem;}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {color:#D1DDF0;}
h1,h2,h3 {color:#EEF6FF!important; letter-spacing:-.02em;}
h1 {font-weight:760!important;}
[data-testid="stMetric"] {background:#111F34;border:1px solid #253A52;border-radius:14px;padding:15px;}
[data-testid="stMetricLabel"] {color:#A8BDD4;}
[data-testid="stMetricValue"] {color:#EAF6FF;}
[data-testid="stVerticalBlockBorderWrapper"] > div {border-color:#263B56;}
[data-testid="stDataFrame"] {border-radius:12px; overflow:hidden; border:1px solid #293C55;}
div[data-baseweb="select"] > div {background:#142238!important;border-color:#344867!important;}
.stTextArea textarea, .stTextInput input {background:#142238!important;color:#E6F1FE!important;}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
    background:linear-gradient(120deg,#12BDB5,#307FC7);border:0;color:#061320;font-weight:750;
}
.stButton > button {border-radius:9px;font-weight:620;}
.stTabs [data-baseweb="tab-list"] {gap:1.6rem; border-bottom:1px solid #293D57;}
.stTabs [data-baseweb="tab"] {font-size:.95rem;font-weight:600;}
.stTabs [aria-selected="true"] {color:#49E2D2!important;}
hr {border-color:#24354A;}
.soc-hero {padding:25px 27px 23px; border:1px solid #2C405F; border-radius:18px;
  background:linear-gradient(107deg,rgba(27,55,85,.94) 0%,rgba(17,31,53,.93) 54%,rgba(49,44,100,.62) 100%);
  box-shadow:0 14px 34px rgba(0,0,0,.16); position:relative; overflow:hidden;}
.soc-hero::after {content:"";position:absolute;width:220px;height:220px;right:-75px;top:-90px;
 border:1px solid rgba(65,220,207,.20);border-radius:50%;box-shadow:0 0 0 35px rgba(65,220,207,.032),0 0 0 72px rgba(65,220,207,.023);}
.soc-overline {font-size:.69rem; font-weight:800; letter-spacing:.16em; color:#62DCD1; margin:0 0 7px;}
.soc-title {font-size:2.5rem; font-weight:800; color:#F1F7FF;line-height:1.06;letter-spacing:-.05em;margin:0 0 8px;}
.soc-desc {font-size:.95rem;color:#B8CBE3;margin:0;max-width:720px;}
.soc-status {display:inline-flex;gap:8px;align-items:center;border:1px solid #35576B;background:rgba(25,57,69,.57);padding:5px 11px;border-radius:99px;color:#9EECE3;font-size:.74rem;font-weight:700;margin-bottom:10px;}
.soc-dot {background:#43DAC6;border-radius:50%;width:7px;height:7px;box-shadow:0 0 11px rgba(67,218,198,.8);display:inline-block;}
.soc-card {min-height:122px; padding:18px 18px 16px;border:1px solid #2B405B;border-radius:15px;
 background:linear-gradient(130deg,#16263E,#111E31);position:relative;overflow:hidden;}
.soc-card::before {content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);}
.soc-card__label {font-size:.74rem;letter-spacing:.08em;text-transform:uppercase;color:#B4C8E0;font-weight:650;}
.soc-card__value {font-size:2rem;letter-spacing:-.05em;font-weight:780;color:var(--accent);line-height:1.35;}
.soc-card__note {font-size:.74rem;color:#91A7C4;}
.soc-section {font-size:1.12rem;color:#EFF7FF;font-weight:730;letter-spacing:-.015em;margin:20px 0 5px;}
.soc-eyebrow {color:#89A1BC;font-size:.73rem;letter-spacing:.09em;font-weight:750;text-transform:uppercase;}
.soc-banner {border:1px solid #2A4A5C;background:rgba(21,67,77,.40);padding:12px 16px;border-radius:12px;color:#B3E6E9;font-size:.85rem;line-height:1.55;margin:8px 0 15px;}
.soc-banner--warn {background:rgba(84,63,29,.35);border-color:#755A38;color:#F4D9A3;}
.soc-smallnote {color:#8FA6C3;font-size:.80rem;}
.soc-casehead {padding:18px 20px;border:1px solid #2B425F;border-radius:14px;background:#14243B;margin:6px 0 16px;}
.soc-casehead__title {font-size:1.18rem;font-weight:750;color:#EFF7FF;}
.soc-casehead__meta {color:#A9BDDA;font-size:.79rem;margin-top:5px;}
.soc-chip {border-radius:999px;border:1px solid #3B6680;background:#17334B;color:#65E0D0;padding:3px 10px;font-size:.73rem;font-weight:750;}
.soc-brand {font-weight:850;letter-spacing:.11em;color:#F2F7FE;font-size:1.15rem;}
.soc-brandmark {font-size:1.42rem;color:#39DFD1;}
.soc-brand-sub {color:#8DA6C4;font-size:.68rem;letter-spacing:.12em;font-weight:700;}
</style>
"""
st.markdown(STYLES, unsafe_allow_html=True)


def h(x):
    return escape(str(x), quote=True)


def metric_card(label, value, note, accent):
    return (f'<div class="soc-card" style="--accent:{accent}">'
            f'<div class="soc-card__label">{h(label)}</div>'
            f'<div class="soc-card__value">{h(value)}</div>'
            f'<div class="soc-card__note">{h(note)}</div></div>')


def apply_chart_theme(fig, height=275):
    fig.update_layout(height=height, paper_bgcolor='rgba(0,0,0,0)',
                      plot_bgcolor='rgba(0,0,0,0)',
                      font=dict(family='Segoe UI, sans-serif', color='#B4C6DD', size=12),
                      margin=dict(l=10, r=10, t=24, b=10),
                      showlegend=False, hoverlabel=dict(bgcolor='#18263B', font_color='#F5FAFF'))
    return fig


def severity_name(level):
    if level >= 15:
        return 'Critical'
    if level >= 12:
        return 'High'
    if level >= 7:
        return 'Medium'
    return 'Low'


def activity_chart(alerts):
    hour_counts = Counter(datetime.fromisoformat(a['timestamp']).astimezone(timezone.utc).replace(
        minute=0, second=0, microsecond=0) for a in alerts)
    keys = sorted(hour_counts)
    vals = [hour_counts[k] for k in keys]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=keys, y=vals, mode='lines+markers',
        line=dict(color=COLORS['cyan'], width=3, shape='spline'),
        marker=dict(size=7, color=COLORS['cyan'], line=dict(color='#0B1322', width=1)),
        fill='tozeroy', fillcolor='rgba(57,223,209,0.12)',
        hovertemplate='%{x|%b %d, %H:%M} UTC<br><b>%{y}</b> alerts<extra></extra>'))
    apply_chart_theme(fig)
    fig.update_xaxes(showgrid=False, color='#8BA5C2', tickformat='%H:%M',
                     title_text='Time (UTC)', title_font=dict(size=10))
    fig.update_yaxes(showgrid=True, gridcolor='#24364C', rangemode='tozero',
                     zeroline=False, color='#8BA5C2', title_text='Alerts', title_font=dict(size=10))
    return fig


def severity_chart(alerts):
    counts = Counter(severity_name(a['level']) for a in alerts)
    labels = ['Low', 'Medium', 'High', 'Critical']
    palette = ['#38D9CC', '#927FF5', '#FBB96D', '#FF6C87']
    fig = go.Figure(go.Pie(labels=labels, values=[counts.get(k, 0) for k in labels],
              hole=.70, sort=False, textinfo='none',
              marker=dict(colors=palette, line=dict(color='#111D30', width=3)),
              hovertemplate='%{label}: <b>%{value}</b><extra></extra>'))
    apply_chart_theme(fig)
    fig.update_layout(annotations=[dict(text=f'<b>{len(alerts)}</b><br><span style="font-size:11px">alerts</span>',
                                         x=.5, y=.5, showarrow=False,
                                         font=dict(size=22, color='#EAF4FF'))])
    return fig, counts


def normalize_live_rows(rows):
    alerts, errors, seen = [], [], set()
    for index, record in enumerate(rows, 1):
        try:
            item = normalize_alert(record)
            if item['alert_id'] in seen:
                continue
            seen.add(item['alert_id'])
            alerts.append(item)
        except (ValueError, TypeError, KeyError) as e:
            errors.append(f'Alert {index}: {e}')
    alerts.sort(key=lambda a: (a['timestamp'], a['alert_id']))
    return alerts, errors


with st.sidebar:
    st.markdown('<div class="soc-brand"><span class="soc-brandmark">⬡ </span> SENTINELSOC</div>'
                '<div class="soc-brand-sub">ANALYST WORKBENCH / V3</div>', unsafe_allow_html=True)
    st.divider()
    st.markdown('<div class="soc-eyebrow">DATA SOURCE</div>', unsafe_allow_html=True)
    source = st.radio('Data mode', ['Offline sample', 'Live via SSH tunnel', 'Synthetic correlation demo'],
                      label_visibility='collapsed', index=0)
    if source == 'Live via SSH tunnel':
        st.caption('On-demand recent alerts from Wazuh Indexer through a local SSH tunnel.')
        lookback = st.select_slider('Lookback window', options=[1, 6, 12, 24, 48, 72], value=24,
                                    format_func=lambda n: f'{n} hours')
        sync = st.button('↻  Sync alerts now', width='stretch', type='primary')
        auto_refresh = st.toggle('Auto-sync every 60 seconds', value=False, key='auto_sync')
        st.caption('Automatic sync runs while this browser session is open.')
    else:
        st.caption('Select Offline sample for real sanitized events or Synthetic correlation demo for clearly labeled fabricated test events.')
        lookback, sync, auto_refresh = 24, False, False
    st.divider()
    st.markdown('<div class="soc-eyebrow">SECURITY NOTES</div>', unsafe_allow_html=True)
    st.caption('• Cases are investigative clusters, not verified incidents.\n\n'
               '• Credentials remain outside the repository.\n\n'
               '• This dashboard is for a private lab.')

@st.fragment(run_every='60s' if source == 'Live via SSH tunnel' and auto_refresh else None)
def render_workbench():
    if source == 'Live via SSH tunnel':
        try:
            cfg = st.secrets.get('indexer', {})
            username = str(cfg.get('username', ''))
            password = str(cfg.get('password', ''))
            url = str(cfg.get('url', 'https://127.0.0.1:9200'))
            verify = cfg.get('verify_tls', True)
            ca = cfg.get('ca_bundle', None)
            legacy_ca_compat = bool(cfg.get('legacy_ca_compat', False))
            correlation_key = str(cfg.get('correlation_key', '')).strip() or None
        except Exception:
            cfg, username, password, url, verify, ca, legacy_ca_compat, correlation_key = {}, '', '', '', True, None, False, None
        if not username or not password or username == 'YOUR_READ_ONLY_INDEXER_USER':
            st.warning('Live mode is not configured yet. Copy `.streamlit/secrets.toml.example` to '
                       '`.streamlit/secrets.toml` and enter your local Indexer credentials. '
                       'Then establish the SSH tunnel. See README for the instructions.')
            st.stop()
        key_fp = sha256(correlation_key.encode()).hexdigest()[:12] if correlation_key else None
        cache_key = ('_live_alerts', url, username, lookback, bool(verify), ca, legacy_ca_compat, key_fp)
        now_utc = datetime.now(timezone.utc)
        requested = should_fetch_live(
            force=sync, auto_refresh=auto_refresh, key=cache_key,
            saved_key=st.session_state.get('_live_key'),
            last_attempt=st.session_state.get('_live_last_attempt'), now=now_utc)
        sync_error = None
        if requested:
            st.session_state['_live_last_attempt'] = now_utc
            try:
                with st.spinner('Reading recent Wazuh alerts through localhost tunnel...'):
                    fresh = fetch_recent_alerts(
                        url, username, password, verify_tls=bool(verify), ca_bundle=ca,
                        legacy_ca_compat=legacy_ca_compat, hours=lookback,
                        correlation_key=correlation_key)
                st.session_state['_live_alerts'] = fresh
                st.session_state['_live_key'] = cache_key
                st.session_state['_live_fetched_at'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                st.session_state.pop('_live_sync_error', None)
            except LiveSourceError as exc:
                sync_error = str(exc)
                st.session_state['_live_sync_error'] = sync_error
                # Only reuse prior alerts when they belong to these same connection settings.
                if st.session_state.get('_live_key') != cache_key or '_live_alerts' not in st.session_state:
                    st.error(sync_error)
                    st.stop()
        if sync_error or st.session_state.get('_live_sync_error'):
            st.warning('Latest live sync failed. Displaying the last successful data. '
                       + (sync_error or st.session_state['_live_sync_error']))
        alerts, bad = normalize_live_rows(st.session_state['_live_alerts'])
        mode_label = 'LIVE · AUTO 60s' if auto_refresh else 'LIVE · ON-DEMAND'
        subtitle = ('Recent Wazuh Indexer alerts through your local SSH tunnel. '
                    + ('Automatically refreshes every 60 seconds while open.' if auto_refresh
                       else 'Use Sync alerts now to retrieve the latest data.'))
        legacy_notice = (bool(verify) and legacy_ca_compat)
        if not verify:
            st.warning('CA/hostname verification is disabled. For production, enable certificate verification.')
    else:
        is_demo = source == 'Synthetic correlation demo'
        alerts, bad = load_jsonl(ROOT / 'data' / 'synthetic-correlation-demo.jsonl' if is_demo else DATA)
        mode_label = 'DEMO · SYNTHETIC TEST EVENTS' if is_demo else 'OFFLINE · SANITIZED SAMPLE'
        subtitle = ('Fabricated events for testing the correlation logic, NOT actual security incidents.' if is_demo
                    else 'Evidence-based security triage powered by your authorized Wazuh lab alerts.')
        legacy_notice = False
        correlation_key = None

    if not alerts:
        st.error('No valid alerts loaded. Check your offline sample or live Indexer query.')
        st.stop()

    if source == 'Synthetic correlation demo':
        st.warning('SYNTHETIC TEST DATA — these events are invented for testing and must NEVER be presented as a real Wazuh investigation.')

    cases = group_cases(alerts)
    timelines = build_timelines(alerts)
    conn = connect(DB)
    if source == 'Live via SSH tunnel':
        sync_escalations(conn, cases)
    status_by_id = {c['case_id']: get_review(conn, c['case_id'])['status'] for c in cases}
    statuses = Counter(status_by_id.values())

    st.markdown(f'''<div class="soc-hero">
        <div class="soc-status"><span class="soc-dot"></span>{h(mode_label)}</div>
        <div class="soc-overline">SECURITY OPERATIONS / INCIDENT TRIAGE</div>
        <div class="soc-title">Your SOC. One clear view.</div>
        <p class="soc-desc">{h(subtitle)}</p>
      </div>''', unsafe_allow_html=True)
    st.write('')
    if source == 'Live via SSH tunnel':
        st.caption('Last successful sync: ' + st.session_state.get('_live_fetched_at', 'Not yet synced')
                   + (' · Automatic refresh enabled' if auto_refresh else ' · Manual refresh'))

    stats = [
        ('Alerts ingested', len(alerts), 'Normalized security events', COLORS['cyan']),
        ('Review clusters', len(cases), 'Investigation candidates', COLORS['violet']),
        ('Under review', statuses.get('Investigating', 0), 'Analyst work in progress', COLORS['blue']),
        ('Escalated', statuses.get('Escalated', 0), 'Require human attention', COLORS['amber']),
    ]
    for col, (name, val, note, color) in zip(st.columns(4, gap='medium'), stats):
        with col:
            st.markdown(metric_card(name, val, note, color), unsafe_allow_html=True)

    if bad:
        st.caption(f'{len(bad)} invalid source rows skipped. View source validation in tests; no raw fields are retained.')

    st.markdown('<div class="soc-banner">🛡️ <b>Analyst note:</b> Investigation timelines are not confirmed attack chains. '
                'Strong entity links require matching pseudonymous identifiers; other links are endpoint/time context only.</div>',
                unsafe_allow_html=True)
    if source == 'Live via SSH tunnel' and not correlation_key:
        st.info('Advanced entity correlation is currently disabled. Add a private `correlation_key` to '
                '`.streamlit/secrets.toml` and sync again. Time-only timelines can still be reviewed.')

    main_tab, chain_tab, queue_tab, response_tab, about_tab = st.tabs(['◈  Operations overview', '⛓  Correlation timelines', '⌕  Investigation queue', '🚨  Escalation inbox', '▤  Methodology & evidence'])

    with main_tab:
        col_activity, col_sev = st.columns([1.55, 1], gap='large')
        with col_activity:
            st.markdown('<div class="soc-section">Detection activity</div><div class="soc-smallnote">Hourly security events · UTC</div>',
                        unsafe_allow_html=True)
            st.plotly_chart(activity_chart(alerts), width='stretch', config={'displayModeBar':False}, key='activity')
        with col_sev:
            st.markdown('<div class="soc-section">Severity distribution</div><div class="soc-smallnote">Wazuh alert level bands</div>',
                        unsafe_allow_html=True)
            fig, severities = severity_chart(alerts)
            st.plotly_chart(fig, width='stretch', config={'displayModeBar':False}, key='severity')
            st.caption(' · '.join(f'{k}: {severities.get(k,0)}' for k in ['Low','Medium','High','Critical']))
        st.markdown('<div class="soc-section">Priority review queue</div>', unsafe_allow_html=True)
        priority = sorted(cases, key=lambda c: (c['score'], c['first_seen']), reverse=True)
        st.dataframe([{'Case': c['case_id'], 'Category': c['category'], 'Score / 100': c['score'],
                       'Alerts': c['alert_count'], 'Status': status_by_id[c['case_id']],
                       'Last seen (UTC)': c['last_seen'][:16].replace('T', ' ')} for c in priority[:10]],
                     width='stretch', hide_index=True,
                     column_config={'Score / 100':st.column_config.ProgressColumn('Priority score',min_value=0,max_value=100,format='%d')})
        st.caption('Select the Investigation queue tab to review case evidence and record decisions.')
        pending_escalations = sum(r['state'] == 'Queued' for r in list_escalations(conn))
        st.caption(f'Automatic local escalation recommendations awaiting review: {pending_escalations}.')

    with chain_tab:
        st.markdown('<div class="soc-section">Multi-signal investigation timelines</div>', unsafe_allow_html=True)
        st.caption('Correlates Wazuh authentication, Sysmon process, and file-integrity alerts within a strict '
                   '15-minute endpoint window. Association is not evidence of compromise.')
        c1, c2, c3 = st.columns(3)
        c1.metric('Process-GUID evidence', sum(t['evidence_level'] == 'high' for t in timelines))
        c2.metric('Shared account/file only', sum(t['evidence_level'] == 'medium' for t in timelines))
        c3.metric('Endpoint/time only', sum(t['evidence_level'] == 'context' for t in timelines))
        st.caption('Evidence strength measures a link between records, not whether an attack occurred.')
        if not timelines:
            st.info('No multi-signal timelines in the current sample. Try a wider lookback; '
                    'this does not prove there was no suspicious activity.')
        else:
            filter_choice = st.selectbox('Relationship evidence filter',
                ['All candidate timelines', 'Process GUID (high)',
                 'Shared account/file (medium)', 'Endpoint/time only (context)'])
            selected_strength = {
                'Process GUID (high)': 'high',
                'Shared account/file (medium)': 'medium',
                'Endpoint/time only (context)': 'context',
            }.get(filter_choice)
            candidates = [t for t in timelines if selected_strength is None
                          or t['evidence_level'] == selected_strength]
            if not candidates:
                st.info('No candidate timelines match the selected evidence filter.')
            else:
                selection = st.selectbox('Select timeline', [t['timeline_id'] for t in candidates],
                            format_func=lambda tid: next(
                                f"{x['first_seen'][:16].replace('T',' ')} UTC · {', '.join(x['signal_types'])} · {x['relationship']} · {tid}"
                                for x in candidates if x['timeline_id'] == tid))
                timeline = next(t for t in candidates if t['timeline_id'] == selection)
                st.markdown(f'<div class="soc-casehead"><div class="soc-casehead__title">'
                            f'{h(timeline["timeline_id"])} · {h(timeline["relationship"])}'
                            f'</div><div class="soc-casehead__meta">{h(timeline["agent"])} · '
                            f'{h(timeline["first_seen"])} → {h(timeline["last_seen"])}</div></div>',
                            unsafe_allow_html=True)
                st.warning(timeline['limitation'])
                st.caption('Record relationship: ' + timeline['evidence_level'].upper()
                           + ' · Process links: ' + str(timeline['high_links'])
                           + ' · Account/file links: ' + str(timeline['medium_links'])
                           + ' · Time-only links: ' + str(timeline['context_links']))
                st.markdown('**Timeline evidence — UTC**')
                st.dataframe([{
                    'Time (UTC)': e['timestamp'].replace('T', ' ')[:19],
                    'Signal': e.get('source_kind') or e['category'],
                    'Rule ID': e['rule_id'],
                    'Severity': e['level'],
                    'Source ref': e.get('event_ref') or 'not available',
                    'Description': e['description'],
                    'Process (allowlisted)': e.get('process_name') or '—',
                    'File action': e.get('file_action') or '—',
                } for e in timeline['alerts']], width='stretch', hide_index=True)
                st.markdown('**Potential MITRE ATT&CK techniques — rule-based**')
                attack_rows = map_alerts(timeline['alerts'])
                if attack_rows:
                    st.dataframe([{
                        'Technique': r['technique_id'], 'Name': r['technique'],
                        'Tactic': r['tactic'], 'Source identifiers': r['source_count'],
                        'MITRE reference': r['url'],
                    } for r in attack_rows], width='stretch', hide_index=True,
                        column_config={'MITRE reference': st.column_config.LinkColumn('MITRE reference')})
                    with st.expander('Why these techniques were suggested / analyst checks'):
                        for r in attack_rows:
                            st.write(f"**{r['technique_id']} — {r['technique']}**")
                            st.caption(r['reason'] + ' Next step: ' + r['next_action'])
                else:
                    st.caption('No curated ATT&CK mapping from this timeline. FIM changes and isolated authentication failures are intentionally not mapped.')
                st.caption('ATT&CK mappings describe possible behaviors, not verified attacks. Counts are not confidence scores.')
                st.markdown('**Relationship evidence**')
                if timeline['links']:
                    st.dataframe([{
                        'Earlier source': link['from_ref'], 'Later source': link['to_ref'],
                        'Relationship': link['evidence'], 'Link strength': link['strength'],
                    } for link in timeline['links']], width='stretch', hide_index=True)
                else:
                    st.caption('No cross-signal links were available.')
                st.caption(f"{timeline['alert_count']} alert records · "
                           f"{timeline['distinct_source_events']} distinct source events where identifiable · "
                           f"{timeline['verified_links']} shared-entity links (not attack proof)")
                current_t = get_review(conn, timeline['timeline_id'])
                with st.form('timeline_review_form'):
                    allowed_t = ['New', 'Investigating', 'Closed - Benign', 'Escalated']
                    selected_t = st.selectbox('Timeline analyst status', allowed_t,
                        index=allowed_t.index(current_t['status']))
                    notes_t = st.text_area('Evidence assessment and next steps', value=current_t['notes'], height=105)
                    save_t = st.form_submit_button('Save timeline review', type='primary')
                if save_t:
                    save_review(conn, timeline['timeline_id'], selected_t, notes_t)
                    st.success('Timeline review saved to your local audit trail.')
                    st.rerun()
                updated_t = get_review(conn, timeline['timeline_id'])
                st.download_button('↓  Download timeline investigation report',
                                   timeline_report(timeline, updated_t['status'], updated_t['notes']) + attack_report_section(timeline['alerts']),
                                   file_name=f"{timeline['timeline_id']}.md", mime='text/markdown')
                with st.expander('Timeline analyst decision history'):
                    history_t = review_history(conn, timeline['timeline_id'])
                    if history_t:
                        st.dataframe([{'Status': a, 'Recorded UTC': b} for a,b in history_t],
                                     width='stretch', hide_index=True)
                    else:
                        st.caption('No recorded analyst decisions yet.')

    with queue_tab:
        options, detail = st.columns([.91, 1.95], gap='large')
        with options:
            st.markdown('<div class="soc-section">Investigation queue</div>', unsafe_allow_html=True)
            categories = ['All categories'] + sorted({c['category'] for c in cases})
            category = st.selectbox('Detection category', categories)
            status_filter = st.selectbox('Review status', ['All statuses', 'New', 'Investigating', 'Closed - Benign', 'Escalated'])
            filtered = [c for c in cases if (category == 'All categories' or c['category'] == category)
                        and (status_filter == 'All statuses' or status_by_id[c['case_id']] == status_filter)]
            filtered.sort(key=lambda c: (c['score'], c['first_seen']), reverse=True)
            if not filtered:
                st.info('No cases match those filters.')
            else:
                choice = st.selectbox('Select investigation', [c['case_id'] for c in filtered],
                          format_func=lambda cid: next(f'{c["score"]}/100 · {c["category"]} · {cid}'
                                                       for c in filtered if c['case_id']==cid))
                case = next(c for c in filtered if c['case_id'] == choice)
                st.markdown('<div class="soc-eyebrow">CASE QUEUE / SORTED BY PRIORITY</div>', unsafe_allow_html=True)
                st.dataframe([{'Case': c['case_id'], 'Score': c['score'], 'Alerts':c['alert_count']}
                              for c in filtered], width='stretch', hide_index=True,
                             height=min(320, 65 + 36*len(filtered)))
        with detail:
            if filtered:
                st.markdown(f'<div class="soc-casehead"><div class="soc-casehead__title">'
                            f'{h(case["case_id"])} · {h(case["category"])} '
                            f'<span class="soc-chip">{h(status_by_id[case["case_id"]])}</span></div>'
                            f'<div class="soc-casehead__meta">{h(case["first_seen"])} → '
                            f'{h(case["last_seen"])} · {h(case["agent"])} · UTC</div></div>', unsafe_allow_html=True)
                a,b,c = st.columns(3)
                a.metric('Priority score', f'{case["score"]}/100')
                b.metric('Alert records', case['alert_count'])
                c.metric('Detection rules', len(case['rule_counts']))
                st.markdown(f'<div class="soc-banner soc-banner--warn">⚠ {h(case["limitation"])}</div>', unsafe_allow_html=True)
                with st.expander('Why this case was prioritized', expanded=False):
                    for label, pts in case['score_factors']:
                        st.write(f'+{pts} points — {label}')
                    st.caption('Not a calibrated risk probability or confirmed incident.')
                st.markdown('<div class="soc-section">Event evidence</div>', unsafe_allow_html=True)
                st.dataframe([{'UTC timestamp': a['timestamp'], 'Rule ID': a['rule_id'],
                               'Level': a['level'], 'Detection description': a['description']}
                              for a in case['alerts']], width='stretch', hide_index=True,
                             height=min(350, 65 + 35*len(case['alerts'])))
                st.markdown('**Potential MITRE ATT&CK techniques — rule-based**')
                case_attack = map_alerts(case['alerts'])
                if case_attack:
                    st.dataframe([{
                        'Technique': r['technique_id'], 'Name': r['technique'],
                        'Tactic': r['tactic'], 'Source identifiers': r['source_count'],
                        'MITRE reference': r['url'],
                    } for r in case_attack], width='stretch', hide_index=True,
                        column_config={'MITRE reference': st.column_config.LinkColumn('MITRE reference')})
                    with st.expander('Investigation playbook suggestions'):
                        for r in case_attack:
                            st.write(f"**{r['technique_id']} — {r['technique']}**")
                            st.caption(r['reason'] + ' Next step: ' + r['next_action'])
                else:
                    st.caption('No curated ATT&CK mapping for these rules. Do not infer that an unmapped event is benign.')
                render_case_recommendations(case)
                current = get_review(conn, case['case_id'])
                st.markdown('<div class="soc-section">Analyst decision</div>', unsafe_allow_html=True)
                with st.form('review_form'):
                    allowed = ['New', 'Investigating', 'Closed - Benign', 'Escalated']
                    chosen = st.selectbox('Classification / workflow status', allowed, index=allowed.index(current['status']))
                    notes = st.text_area('Evidence, interpretation and next actions', value=current['notes'], height=120)
                    submitted = st.form_submit_button('Save analyst review', type='primary')
                if submitted:
                    save_review(conn, case['case_id'], chosen, notes)
                    st.success('Decision saved with a local audit record.')
                    st.rerun()
                latest = get_review(conn, case['case_id'])
                st.download_button('↓  Download investigation report',
                                   markdown_case_report(case, latest['status'], latest['notes']) + attack_report_section(case['alerts']) + response_report_section(case),
                                   file_name=f'{case["case_id"]}.md', mime='text/markdown')
                with st.expander('Decision history'):
                    history = review_history(conn, case['case_id'])
                    if history:
                        st.dataframe([{'Decision': row[0], 'Recorded at (UTC)':row[1]} for row in history],
                                     hide_index=True, width='stretch')
                    else:
                        st.caption('No analyst decisions recorded yet.')

    with response_tab:
        if source == 'Live via SSH tunnel':
            render_escalation_inbox(conn, cases)
            render_notification_handoffs(conn, cases)
        else:
            st.info('The automatic escalation inbox is active in Live via SSH tunnel mode only. '
                    'Offline and synthetic demo alerts cannot create escalation items.')

    with about_tab:
        if legacy_notice:
            with st.expander('Connection security — lab CA compatibility', expanded=False):
                st.info('The Wazuh CA chain and 127.0.0.1 hostname are verified, but Python strict '
                        'X.509 format checks are relaxed because the local CA lacks a required KeyUsage '
                        'extension. Keep using the SSH tunnel and replace this CA before production.')
        st.markdown('<div class="soc-section">Built for evidence, not just appearance</div>', unsafe_allow_html=True)
        st.markdown('''**Pipeline:** Wazuh alerts → selective ingestion → normalization → 15-minute investigation
    clusters → heuristic prioritization → analyst notes / decisions → downloadable Markdown report.

    **Safety:** The provided offline export is sanitized. Live mode uses a read-only query over an SSH
    port forward and deliberately keeps personal account names, IPs, raw log messages and process command
    lines out of the case dataset. The workbench is intended for an authorized, local lab only.

    **Correlation methodology:** The Correlation timelines tab uses a strict 15-minute window on the same endpoint,
    and requires two or more signal categories. It labels time coincidence separately from matching HMAC-linked
    principals, matching Sysmon process GUIDs, and matching file identities. Strong GUID links,
    medium account/file links and time-only context are distinct. It never claims causality.
    A private local secret is needed to create stable pseudonymous identifiers. Raw usernames, command lines,
    IP addresses and file paths are not included in normalized output.

    **Limitations:** Indexer queries retrieve only a limited window of alerts, not all activity. Some process
    actions generate multiple rule alerts. Without an account or process identifier, a multi-signal timeline
    is only a review candidate. Scoring remains heuristic, not a measured breach probability.

    **Portfolio-ready evidence:** Publish the custom Wazuh rules, configuration examples, test results,
    redacted screenshots, source code, and one honest investigation case report. Never commit credentials or
    an unredacted live alert export.''')
        if source == 'Live via SSH tunnel':
            st.caption(f'Latest data retrieval: {st.session_state.get("_live_fetched_at", "Not yet fetched")}')

    st.divider()
    st.caption('SentinelSOC · Local security operations workbench · Authorized lab telemetry only · No automated response actions')


render_workbench()
