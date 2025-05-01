## ☛ `README.md`
```markdown
# latvian‑einvoice

One pip‑installable client for the two official Latvian e‑invoice channels:

| Channel | Uses | Class |
|---------|------|-------|
| **e‑adrese** (VUS/DIV) | State e‑mailbox; XML+PDF rēķini ar `DocumentKindCode="EINVOICE"` | `EAddressClient` |
| **VID EDS API** | Direct REST push to tax authority | `EDSClient` |

* ✅  Handles OAuth2, SOAP or REST details for you  
* 🔐  Supports QWAC/QSeal cert pinning (e‑adrese)  
* 🔄  Easy drop‑in for **Odoo** cron jobs  
* 🧪  **pytest** + **GitHub Actions** CI  

```bash
pip install latvian-einvoice
```
```

---
