# Workflow n8n

I file JSON sono in [`../workflows/`](../workflows/). Import sul lab:

```powershell
powershell -File .\scripts\import-n8n-workflows.ps1
```

Lo script importa i workflow, pubblica Dispatcher, Close e Poller, quindi riavvia n8n affinché i webhook risultino registrati.

## LAB - TI Dispatcher

Webhook GET `/webhook/lab-reputation`. In base ai parametri `ip`, `domain`, `hash` o `cve` esegue le lookup disponibili (o gli stub) e restituisce un report HTML.

```text
http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8
http://localhost:5678/webhook/lab-reputation?domain=example.com
http://localhost:5678/webhook/lab-reputation?hash=d41d8cd98f00b204e9800998ecf8427e
http://localhost:5678/webhook/lab-reputation?cve=CVE-2021-44228
```

## Moduli IP / Domain / Hash / CVE

Stessa logica di enrichment del Dispatcher, esposta come workflow autonomi (pattern analogo a Security Onion). Consentono riuso e collegamento futuro come sub-workflow.

## LAB - Splunk Warning Poller

Esecuzione ogni 5 minuti. Sorgenti: `warning-plus.jsonl` (se generato da `splunk-warning-export.ps1`) oppure i JSON in `/data/winlogs`. Filtra i livelli Avviso/Errore/Critico (e equivalenti EN), applica deduplica su Id+TimeCreated+LogName, apre il triage, invoca il Dispatcher, interroga Ollama se raggiungibile e scrive il report in `/data/soc-reports`.

## LAB - Close Alert

POST `/webhook/lab-close` con `alert_id` (e `owner` opzionale). Aggiunge un evento `status=closed`; in Splunk lo stato corrente si valuta con `latest(status)` per `alert_id`.

## LAB - Manual Demo Pipeline

Trigger manuale in n8n: crea un triage di esempio, chiama il Dispatcher e produce un report, senza attendere lo schedule.

## Rigenerazione JSON

```powershell
python .\scripts\generate-n8n-workflows.py
```

Di default lo script può scrivere anche sotto path del lab NUC. Per un clone isolato di questo repository, aggiornare i path `OUT` / `HUB` nello script.
