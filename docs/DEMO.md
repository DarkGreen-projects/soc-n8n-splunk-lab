# Demo

Prerequisiti: stack lab attivo (Splunk Free, n8n; Ollama opzionale con modello `llama3.2:1b`).

```powershell
powershell -File .\scripts\import-n8n-workflows.ps1
powershell -File .\scripts\demo-soc-pipeline.ps1
powershell -File .\scripts\splunk-warning-export.ps1
```

Risultati attesi da `demo-soc-pipeline.ps1`:

1. Risposta HTML dal Dispatcher (contenuto “LAB IP Reputation”)
2. Eventi sample open/closed nella triage inbox
3. Webhook di chiusura con `ok: true`
4. Nuovo report in `soc-reports/`

Verifiche utili: webhook `?ip=8.8.8.8`, cartella report, workflow LAB in n8n, search Splunk su `index=alerts_triage`.

Non condividere password, file `.env`, log Security reali o report con dati interni non sanitizzati.
