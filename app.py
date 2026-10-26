"""Streamlit UI for the beginner email header analyzer."""

import streamlit as st
from analyzer import analyze_email_headers

st.set_page_config(page_title="Email Header Analyzer", page_icon="🛡️")
st.title("🛡️ Email Header Analyzer")
st.write(
    "Upload an **.eml** file or paste the email's **full original headers** "
    "to inspect SPF, DKIM, DMARC, sender-domain clues and brand lookalikes."
)

uploaded = st.file_uploader("Upload email (.eml or .txt)", type=["eml", "txt"])
pasted = st.text_area(
    "Or paste full email headers here",
    height=180,
    placeholder="From: ...\nAuthentication-Results: ...\nReply-To: ...",
)

if st.button("Analyze headers", type="primary"):
    raw = uploaded.getvalue() if uploaded is not None else pasted.encode("utf-8")
    if not raw.strip():
        st.error("Upload a file or paste email headers first.")
    elif len(raw) > 2_000_000:
        st.error("File too large for this demo (maximum 2 MB).")
    else:
        try:
            result = analyze_email_headers(raw)
        except (ValueError, UnicodeError) as exc:
            st.error(f"Cannot analyze the supplied data: {exc}")
            st.stop()
        st.subheader(result["verdict"])
        st.metric("Heuristic risk score (0–100)", result["score"])
        st.write("**Reasons:**")
        for reason in result["reasons"]:
            st.write(f"- {reason}")

        st.subheader("Brand impersonation indicators")
        if result["brand_findings"]:
            st.table([{
                "Brand": item["brand"],
                "Sender domain": item["sender_domain"],
                "Reference": item["reference"],
                "Finding": item["finding"],
            } for item in result["brand_findings"]])
        else:
            st.write("No configured brand-lookalike indicator found. Not proof of safety.")

        st.subheader("Authentication results (reported, not re-verified)")
        st.table(
            [{"Check": name, "Reported status": status}
             for name, status in result["checks"].items()]
        )
        st.caption(f"Authentication-Results source label: {result['auth_server']}")

        st.subheader("Email header details")
        st.write(f"**From:** {result['from']}")
        st.write(f"**Reply-To:** {result['reply_to']}")
        st.write(f"**Return-Path:** {result['return_path']}")
        st.write(f"**Subject:** {result['subject']}")
        st.write(f"**Received headers:** {result['received_hops']}")

st.info(
    "Educational tool only: the Authentication-Results header can be forged "
    "unless it comes from a trusted receiving mail system. Passing SPF/DKIM/DMARC "
    "does not guarantee an email is harmless."
)
