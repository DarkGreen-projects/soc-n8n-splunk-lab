# Workflow n8n

Export JSON in [`../workflows/`](../workflows/). Importare con [`../scripts/import-n8n-workflows.ps1`](../scripts/import-n8n-workflows.ps1) (pubblica Dispatcher, Close, Poller e riavvia n8n).

## LAB - TI Dispatcher

- **Trigger:** Webhook GET `/webhook/lab-reputation`
- **Input:** query `ip` | `domain` | `hash` | `cve`
- **Output:** HTML (`Content-Type: text/html`)
- **Logica:** Switch sul tipo IOC → HTTP free API o stub → template report

Esempi:

```text
http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8
http://localhost:5678/webhook/lab-reputation?domain=example.com
http://localhost:5678/webhook/lab-reputation?hash=d41d8cd98f00b204e9800998ecf8427e
http://localhost:5678/webhook/lab-reputation?cve=CVE-2021-44228
```

## LAB - IP / Domain / Hash / CVE Reputation

Moduli autonomi (`Execute Workflow Trigger`) allineati al pattern Security Onion:

- riusabili come sub-workflow
- stessa logica free/stub del Dispatcher
- utili per estendere il lab senza toccare il webhook principale

## LAB - Splunk Warning Poller

- **Trigger:** ogni 5 minuti
- **Detection:**  
  1. `/data/n8n-state/warning-plus.jsonl` (host: `splunk-warning-export.ps1`)  
  2. fallback `/data/winlogs/*.json`
- **Dedup:** hash `Id|TimeCreated|LogName` in `seen-alerts.json`
- **Azioni:** scrive open triage → chiama Dispatcher → Ollama → salva HTML in `/data/soc-reports`

Livelli Windows (IT/EN): `Avviso`/`Warning`, `Errore`/`Error`, `Critico`/`Critical`.

## LAB - Close Alert

- **Trigger:** POST `/webhook/lab-close`
- **Body:** `{ "alert_id": "...", "owner": "demo" }`
- **Effetto:** nuovo evento JSON `status=closed` (Splunk aggiorna i contatori `latest(status)`)

## LAB - Manual Demo Pipeline

Trigger manuale in UI n8n: crea un open sample, chiama Dispatcher, scrive report — utile quando non si vuole attendere lo schedule.

## Rigenerare i JSON

```powershell
python .\scripts\generate-n8n-workflows.py
```

Lo script scrive anche sotto `C:\lab\exports\n8n-workflows` se presente (lab NUC). Per il solo repo, adattare i path `OUT` / `HUB` nello script.
