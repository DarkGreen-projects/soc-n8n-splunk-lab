# Demo e checklist colloquio

## Prerequisiti

- Docker Desktop con stack lab (Splunk Free, n8n, Ollama)
- Workflow importati e pubblicati (Dispatcher, Close, Poller)
- (Opzionale) `ollama pull llama3.2:1b`

## Sequenza consigliata

```powershell
# 1) Import + publish
powershell -File .\scripts\import-n8n-workflows.ps1

# 2) Smoke test end-to-end
powershell -File .\scripts\demo-soc-pipeline.ps1

# 3) Bridge Warning+ da Splunk (Free-compatible)
powershell -File .\scripts\splunk-warning-export.ps1
```

Esiti attesi di `demo-soc-pipeline.ps1`:

1. Dispatcher HTML OK (contiene "LAB IP Reputation")
2. Sample open/closed in triage inbox
3. Close webhook `ok: true`
4. Report HTML in `soc-reports/`

## Screenshot utili (portfolio / LinkedIn)

| # | Cosa catturare | Perché |
| --- | --- | --- |
| 1 | Browser su `lab-reputation?ip=8.8.8.8` | TI live + stub espliciti |
| 2 | Cartella `soc-reports` con `demo-*.html` / `auto-*.html` | Artefatti concreti |
| 3 | n8n: workflow LAB pubblicati | Orchestration visibile |
| 4 | Splunk search `index=alerts_triage` | SIEM collegato al triage |
| 5 | (Opzionale) sezione AI nel report | Interesse SOC + IA |

## Talking points

- Separazione SIEM / SOAR su licenza Free  
- Dedup e stato open/closed senza Enterprise Security  
- Enrichment onesto (free + stub, non fingere API key)  
- Estendibilità: slot VT/Shodan/MISP / notifiche Telegram future  

## Cosa non mostrare

- Password Splunk / `.env`  
- Log Security reali con account interni  
- Report con hostname/IP privati non sanitizzati  
