"""Streamlit views for local, analyst-approved response workflow."""
import streamlit as st
from workbench.response import response_plan
from workbench.escalation import list_escalations, decide_escalation, escalation_history


def render_case_recommendations(case):
    p = response_plan(case)
    st.markdown('**Suggested incident response — human review required**')
    st.caption(f"Automatic escalation recommendation: {p['priority'] or 'Routine review'} · {p['reason']}")
    st.dataframe([{'Phase': x['phase'], 'Recommended analyst action': x['action'],
                   'Approval before action': 'Required' if x['approval'] else 'Not applicable'}
                  for x in p['actions']], width='stretch', hide_index=True)
    st.caption(p['safety_note'])


def render_escalation_inbox(conn, cases):
    st.markdown('### Automated escalation inbox')
    st.caption('Risk-based suggestions are queued locally, once per case. A queue entry is NOT an incident confirmation, '
               'an external notification, or permission to isolate a host. Analysts control every change.')
    all_rows = list_escalations(conn)
    a,b,c = st.columns(3)
    a.metric('Pending review', sum(r['state']=='Queued' for r in all_rows))
    b.metric('Acknowledged', sum(r['state']=='Acknowledged' for r in all_rows))
    c.metric('Analyst-escalated', sum(r['state']=='Escalated' for r in all_rows))
    choice = st.selectbox('Inbox filter', ['All', 'Queued', 'Acknowledged', 'Escalated', 'Dismissed'],
                          key='escalation_inbox_filter')
    rows = [r for r in all_rows if choice=='All' or r['state']==choice]
    if not rows:
        st.info('No escalation recommendations match this filter. This can be normal for low-severity telemetry.')
        return
    st.dataframe([{'Case': r['case_id'], 'Priority': r['priority'], 'Score': r['score'],
                   'State': r['state'], 'Queued UTC': r['queued_at'][:19].replace('T',' ')}
                  for r in rows], hide_index=True, width='stretch')
    labels = [r['case_id'] for r in rows]
    selected_id = st.selectbox('Select queued case', labels, key='escalation_case_choice')
    row = next(r for r in rows if r['case_id']==selected_id)
    st.write(f"**{row['priority']} · {row['case_id']} · {row['state']}**")
    st.caption(row['reason'])
    case = next((c for c in cases if c['case_id']==selected_id), None)
    if case:
        with st.expander('Recommended response checklist', expanded=True):
            render_case_recommendations(case)
    else:
        st.caption('This queued case is not present in the current lookback window; its stored reason and decision history remain available.')
    options = {
        'Queued': ['Acknowledge', 'Escalate', 'Dismiss'],
        'Acknowledged': ['Escalate', 'Dismiss'],
        'Escalated': [], 'Dismissed': [],
    }[row['state']]
    if options:
        with st.form('escalation_decision_form'):
            decision = st.selectbox('Human decision', options)
            notes = st.text_area('Reason / handoff notes (required for Escalate or Dismiss)',
                                 max_chars=2000, height=95)
            submitted = st.form_submit_button('Record decision', type='primary')
        if submitted:
            state = {'Acknowledge':'Acknowledged', 'Escalate':'Escalated', 'Dismiss':'Dismissed'}[decision]
            try:
                decide_escalation(conn, selected_id, state, notes)
            except ValueError as exc:
                st.error(str(exc))
            else:
                st.success('Decision saved locally with an audit entry. No external notification or endpoint action was sent.')
                st.rerun()
    else:
        st.caption('This suggestion has a final decision; sync will not automatically reopen it.')
    with st.expander('Escalation decision history'):
        history = escalation_history(conn, selected_id)
        st.dataframe([{'Action': x, 'Reason': y, 'UTC': z} for x,y,z in history],
                     width='stretch', hide_index=True)
