# Security

If you find a vulnerability, **please do not open a public issue**: use GitHub private reporting
("Security" → "Report a vulnerability").

Project principles:
- links in emails are never opened and attachments are never executed;
- email data is never sent to external services (threat feeds are downloaded and matched locally);
- SPF/DKIM/DMARC "pass" only counts when written by a trusted receiving server or when the DKIM
  signature is verified cryptographically; negative results always count;
- size and complexity limits protect against emails crafted to stall the analysis.

Never commit real emails, credentials, configuration files or reports.

---

🇮🇹 Se trovi una vulnerabilità non aprire una issue pubblica: usa la segnalazione privata di GitHub
("Security" → "Report a vulnerability").
