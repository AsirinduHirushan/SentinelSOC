"""Streamlit UI for analyst-approved incident handoff and notification audit."""
import json
from workbench.escalation import list_escalations
from workbench.notifications import (
    NotificationError, delivery_audit, delivery_rows,
    format_handoff, handoff_preview, send_approved_handoff, mark_stale_sending_uncertain,
    validate_channel_config,
)
import streamlit as st


def _config():
    try:
        return st.secrets.get('notifications', {})
    except Exception:
        # Streamlit may have no .streamlit/secrets.toml at all.
        return {}


def render_notification_handoffs(conn, cases):
    st.divider()
    st.markdown('### Incident handoffs & notification delivery')
    st.caption('The Escalation inbox is local by default. Only an analyst-approved Escalated case can be sent '
               'externally, and only after clicking Send. No endpoint commands are executed.')
    rows = delivery_rows(conn)
    left, mid, right = st.columns(3)
    left.metric('Accepted', sum(r['status']=='Accepted' for r in rows))
    mid.metric('Needs attention', sum(r['status'] in ('Failed','Uncertain') for r in rows))
    right.metric('In progress', sum(r['status']=='Sending' for r in rows))
    if rows:
        st.dataframe([{'Case':r['case_id'], 'Channel':r['channel'],
                       'Status':r['status'], 'Attempts':r['attempts'],
                       'Target':r['target_label'], 'UTC':r['updated_at'][:19].replace('T',' ')}
                      for r in rows], width='stretch', hide_index=True)
    escalated = list_escalations(conn, state='Escalated')
    if not escalated:
        st.info('No analyst-escalated cases yet. First use Human decision → Escalate '
                'on a verified lab case in the inbox above.')
        return
    chosen = st.selectbox('Case to hand off', [r['case_id'] for r in escalated],
                          key='notification_case_choice')
    selected = next(r for r in escalated if r['case_id']==chosen)
    st.caption(f"{selected['priority']} · heuristic score {selected['score']}/100 · "
               'Analyst approval required for each delivery channel.')
    settings = _config()
    enabled = settings.get('enabled') is True if hasattr(settings,'get') else False
    channels = []
    problems = []
    if enabled:
        for ch in ('webhook', 'email'):
            if settings.get(ch):
                try:
                    validate_channel_config(settings, ch)
                except NotificationError as ex:
                    problems.append(f'{ch}: {ex}')
                else:
                    channels.append(ch)
    if not enabled:
        st.info('External delivery is OFF. Prepare a local handoff document now, or configure '
                '[notifications] in your private .streamlit/secrets.toml to enable email/webhook sending.')
    for problem in problems:
        st.warning(problem)
    ch = st.selectbox('Delivery channel', channels, key='notification_channel') if channels else None
    previous = next((r for r in rows if r['case_id']==chosen and r['channel']==ch), None) if ch else None
    if previous:
        st.write(f"**Previous delivery:** {previous['status']} · {previous['attempts']} attempt(s) · "
                 f"{previous['last_code']}")
    summary = st.text_area('Brief handoff summary (will be included in outbound message)',
                           key=f'notification_summary_{chosen}', height=105,
                           max_chars=500, placeholder='Reason for escalation and requested next analyst action. '
                           'Do not include raw log contents, credentials, usernames or personal data.')
    try:
        preview = handoff_preview(conn, chosen, summary)
    except NotificationError:
        st.caption('Enter at least 8 characters to preview the approved handoff document.')
        preview = None
    if preview:
        with st.expander('Preview outbound handoff fields', expanded=False):
            if ch == 'webhook':
                st.code(json.dumps(preview, indent=2), language='json')
            else:
                st.code(format_handoff(preview), language='text')
        st.download_button('↓ Download handoff report (.md)', format_handoff(preview),
                           file_name=f'{chosen}-handoff.md', mime='text/markdown',
                           key=f'notification_download_{chosen}')
    if ch and preview:
        if previous and previous['status']=='Accepted':
            st.success('Provider already accepted this case/channel. Duplicate sending is blocked.')
        elif previous and previous['status']=='Sending':
            st.warning('Previously started send is not confirmed finished. Inspect the recipient/provider '
                       'before retrying; the app will not send a duplicate automatically.')
            if st.button('Mark interrupted send as uncertain', key=f'interrupted_{chosen}_{ch}'):
                try:
                    mark_stale_sending_uncertain(conn, chosen, ch)
                except NotificationError as ex:
                    st.error(str(ex))
                else:
                    st.rerun()
        else:
            with st.form('notification_send_approval'):
                st.caption('The destination is configured by the operator; never sourced from alerts or form input.')
                approved = st.checkbox('I have reviewed this case and approve external delivery '
                                       'of the previewed summary.')
                retry = bool(previous and previous['status'] in ('Failed', 'Uncertain'))
                verified = False
                if retry and previous['status']=='Uncertain':
                    verified = st.checkbox('I verified with the recipient/provider that the earlier '
                                           'attempt was not delivered. I accept duplicate-delivery risk.')
                submit = st.form_submit_button('Approve & send notification', type='primary')
            if submit:
                if not approved:
                    st.error('Explicit approval is required before sending.')
                else:
                    try:
                        result = send_approved_handoff(conn, chosen, ch, summary, settings,
                                                       retry=retry, verified_not_delivered=verified)
                    except NotificationError as ex:
                        st.error(str(ex))
                    else:
                        if result['state']=='Accepted':
                            st.success('Provider accepted the notification (recipient receipt is not guaranteed). Logged in local SQLite.')
                        elif result['state']=='Failed':
                            st.error('Provider rejected the notification; check private configuration and retry manually.')
                        else:
                            st.warning('Delivery is uncertain. Check recipient/provider before any retry.')
                        st.rerun()
    with st.expander('Notification delivery audit history'):
        audit = delivery_audit(conn, chosen)
        if audit:
            st.dataframe([{'Channel':x, 'Event':y, 'Detail':z, 'UTC':ts}
                          for x,y,z,ts in audit], width='stretch', hide_index=True)
        else:
            st.caption('No notification attempts recorded for this case.')
