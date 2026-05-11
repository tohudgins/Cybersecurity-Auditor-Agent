# Demo Artifacts

Sample inputs to exercise each audit path. All files are deliberately weak — do not deploy any of them.

| File | Audit kind | What it triggers |
|---|---|---|
| `sshd_config_weak.conf` | config | Root SSH login, password auth, empty passwords, X11 forwarding |
| `Dockerfile_root.txt` | config | `:latest` tag, no `USER`, `ADD <url>` |
| `auth_bruteforce.log` | log | Brute-force pattern + successful root login + suspicious post-login activity |
| `policy_minimal.txt` | text / config | Internal policy missing MFA, IR, audit logging, encryption-at-rest |
| `terraform_open_sg.tf` | config | `0.0.0.0/0` ingress, public S3 ACL, unencrypted RDS, hard-coded password |

## Running the demo

```bash
streamlit run app.py
```

Then in the sidebar, upload one or more of these files and submit any prompt (e.g., "audit this"). The findings panel renders the structured report.

## Notes

- `Dockerfile_root.txt` is named with a `.txt` extension because Streamlit's file uploader rejects extension-less files. The `audit_config` detector matches on `"dockerfile"` substring in the lowercased filename, so it still routes correctly.
- `policy_minimal.txt` will be classified as `config` by the current uploader (only `.pdf` triggers the `policy_pdf` path). For the policy-vs-framework path, paste the contents into the chat or supply a real PDF.
