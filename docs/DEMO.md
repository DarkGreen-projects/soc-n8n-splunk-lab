# Provare la demo

Ti serve lo stack su (Splunk, n8n, eventualmente Ollama con `llama3.2:1b`).

```powershell
powershell -File .\scripts\import-n8n-workflows.ps1
powershell -File .\scripts\demo-soc-pipeline.ps1
powershell -File .\scripts\splunk-warning-export.ps1
```

Se `demo-soc-pipeline` va bene, di solito vedi:

- HTML dal Dispatcher (testo tipo “LAB IP Reputation”)
- un paio di JSON sample in triage (open + closed)
- close webhook con `ok: true`
- un report nuovo in `soc-reports/`

Cose utili da aprire a mano: il webhook `?ip=8.8.8.8`, la cartella report, n8n con i workflow LAB, Splunk su `index=alerts_triage`.

Non mettere in giro password, `.env`, log Security veri o HTML con hostname/account interni.
