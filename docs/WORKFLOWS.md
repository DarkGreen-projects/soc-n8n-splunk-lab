# Workflow n8n

I JSON stanno in [`../workflows/`](../workflows/). Per caricarli sul lab:

```powershell
powershell -File .\scripts\import-n8n-workflows.ps1
```

Lo script importa, pubblica Dispatcher / Close / Poller e riavvia n8n (i webhook si registrano al restart).

## LAB - TI Dispatcher

Webhook GET `/webhook/lab-reputation`. Guardi i query param (`ip`, `domain`, `hash`, `cve`), fai le chiamate free o metti lo stub, e rispondi con una pagina HTML.

```text
http://localhost:5678/webhook/lab-reputation?ip=8.8.8.8
http://localhost:5678/webhook/lab-reputation?domain=example.com
http://localhost:5678/webhook/lab-reputation?hash=d41d8cd98f00b204e9800998ecf8427e
http://localhost:5678/webhook/lab-reputation?cve=CVE-2021-44228
```

## Moduli IP / Domain / Hash / CVE

Stessa logica del Dispatcher, ma come workflow richiamabili a parte (pattern tipo Security Onion). Li tengo così se un giorno collego il Dispatcher ai sub-workflow per ID invece di tenere tutto inline.

## LAB - Splunk Warning Poller

Parte ogni 5 minuti. Prima legge `warning-plus.jsonl` (se l’hai generato con `splunk-warning-export.ps1`), altrimenti scorre i JSON in `/data/winlogs`. Filtra Avviso/Errore/Critico (e i nomi EN), evita i duplicati con uno hash su Id+TimeCreated+LogName, apre il triage, chiama il Dispatcher, prova Ollama, scrive l’HTML in `/data/soc-reports`.

## LAB - Close Alert

POST `/webhook/lab-close` con `alert_id` (e `owner` se vuoi). Non “aggiorna” il file vecchio: aggiunge un evento `closed`. In Splunk usi `latest(status)` per alert.

## LAB - Manual Demo Pipeline

Bottone Execute in n8n: crea un open finto, chiama il Dispatcher, scrive un report. Comodo quando non vuoi aspettare lo schedule.

## Rigenerare i JSON

```powershell
python .\scripts\generate-n8n-workflows.py
```

Di default lo script punta anche a path del lab NUC (`C:\lab\...`). Se lavori solo da questo clone, sistema `OUT` / `HUB` nello script.
