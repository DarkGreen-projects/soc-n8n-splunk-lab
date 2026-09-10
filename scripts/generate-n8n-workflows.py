#!/usr/bin/env python3
"""Generate LAB SOC n8n workflow JSON files (portfolio demo, no paid API keys)."""
from __future__ import annotations

import json
import secrets
from pathlib import Path

OUT = Path(r"C:\lab\exports\n8n-workflows")
HUB = Path(r"C:\Users\feded\Projects\soc-automation-hub\docs\lab-n8n\workflows")


def new_id(n=16):
    return secrets.token_hex(n // 2)


def node(nid, name, ntype, params, pos, **extra):
    d = {
        "parameters": params,
        "id": nid,
        "name": name,
        "type": ntype,
        "typeVersion": extra.pop("typeVersion", 1),
        "position": pos,
    }
    d.update(extra)
    return d


def conn(src, dst, src_out=0, dst_in=0):
    return {src: {"main": [[{"node": dst, "type": "main", "index": dst_in}] + ([] if src_out == 0 else [])]}}


def save(name: str, workflow: dict):
    OUT.mkdir(parents=True, exist_ok=True)
    HUB.mkdir(parents=True, exist_ok=True)
    clean = json.loads(json.dumps(workflow))
    if not clean.get("id"):
        clean["id"] = new_id(16)
    if not clean.get("versionId"):
        clean["versionId"] = new_id(16)
    for n in clean.get("nodes", []):
        n.pop("credentials", None)
        if not n.get("id"):
            n["id"] = new_id(16)
    path = OUT / name
    path.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    (HUB / name).write_text(json.dumps(clean, indent=2), encoding="utf-8")
    print(f"Wrote {path}")


ENRICH_IP_CODE = r"""
const ip = ($json.ip || $json.query?.ip || '').toString().trim();
const geo = $json.geo || {};
const stub = {
  abuseipdb: { provider: 'stub (no API key)', abuseConfidenceScore: 0, totalReports: 0, usageType: 'unknown', note: 'Replace stub with AbuseIPDB when you have a free community key.' },
  shodan: { provider: 'stub (no API key)', ports: [], hostnames: [], note: 'Replace stub with Shodan API when available.' },
  virustotal: { provider: 'stub (no API key)', malicious: 0, suspicious: 0, undetected: 0, harmless: 0, note: 'Replace stub with VirusTotal API when available.' },
  misp: { provider: 'stub (no API key)', events: [], html: 'No MISP instance in this lab demo.' }
};
const country = geo.country || geo.countryCode || 'n/a';
const isp = geo.isp || geo.org || 'n/a';
const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>IP Report ${ip}</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7ecf3}
h1{color:#5eead4}h2{color:#93c5fd;border-bottom:1px solid #334155;padding-bottom:.3rem}
.card{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}a{color:#7dd3fc}.badge{display:inline-block;background:#334155;padding:.15rem .5rem;border-radius:4px;font-size:.85rem}</style></head>
<body><h1>LAB IP Reputation</h1><p class="badge">NUC SOC demo · free/stub TI</p>
<div class="card"><h2>Indicator</h2><p><strong>${ip}</strong></p>
<p>Geo (ip-api.com): ${country} · ISP/Org: ${isp} · City: ${geo.city||'n/a'}</p>
<p>Status: ${geo.status||'unknown'} ${geo.message?('· '+geo.message):''}</p></div>
<div class="card"><h2>AbuseIPDB</h2><p>${stub.abuseipdb.note}</p><p>Score: ${stub.abuseipdb.abuseConfidenceScore} · Reports: ${stub.abuseipdb.totalReports}</p></div>
<div class="card"><h2>Shodan</h2><p>${stub.shodan.note}</p></div>
<div class="card"><h2>VirusTotal</h2><p>${stub.virustotal.note}</p></div>
<div class="card"><h2>MISP</h2><p>${stub.misp.html}</p></div>
<footer><p>Pattern inspired by inthecyber Security Onion n8n workflows · adapted for Splunk Free lab</p></footer>
</body></html>`;
return [{ json: { ip, geo, stub, html, type: 'ip' } }];
"""

ENRICH_DOMAIN_CODE = r"""
const domain = ($json.domain || '').toString().trim().toLowerCase();
const dns = $json.dns || {};
const answers = (dns.Answer || []).map(a => `${a.type}:${a.data}`).join(', ') || 'none';
const stub = {
  virustotal: { provider: 'stub (no API key)', malicious: 0, note: 'Stub — add VT API later.' },
  urlhaus: { provider: 'stub (no API key)', note: 'Stub — optional abuse.ch Auth-Key later.' }
};
const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Domain ${domain}</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7ecf3}
h1{color:#5eead4}h2{color:#93c5fd}.card{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}</style></head>
<body><h1>LAB Domain Reputation</h1>
<div class="card"><h2>Indicator</h2><p><strong>${domain}</strong></p>
<p>DNS (Google JSON): ${answers}</p><p>Status: ${dns.Status}</p></div>
<div class="card"><h2>VirusTotal / URLhaus</h2><p>${stub.virustotal.note}</p><p>${stub.urlhaus.note}</p></div>
</body></html>`;
return [{ json: { domain, dns, stub, html, type: 'domain' } }];
"""

ENRICH_HASH_CODE = r"""
const hash = ($json.hash || '').toString().trim().toLowerCase();
let kind = 'unknown';
if (/^[a-f0-9]{32}$/.test(hash)) kind = 'md5';
else if (/^[a-f0-9]{40}$/.test(hash)) kind = 'sha1';
else if (/^[a-f0-9]{64}$/.test(hash)) kind = 'sha256';
const valid = kind !== 'unknown';
const stub = { virustotal: { provider: 'stub (no API key)', malicious: 0, suspicious: 0, note: 'Stub VT — no paid/free key required for this demo.' } };
const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hash ${hash}</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7ecf3}
h1{color:#5eead4}.card{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}</style></head>
<body><h1>LAB Hash Reputation</h1>
<div class="card"><p><strong>${hash}</strong></p><p>Type: ${kind} · Valid format: ${valid}</p>
<p>${stub.virustotal.note}</p><p>Demo score malicious=${stub.virustotal.malicious}</p></div>
</body></html>`;
return [{ json: { hash, kind, valid, stub, html, type: 'hash' } }];
"""

ENRICH_CVE_CODE = r"""
const cve = ($json.cve || '').toString().trim().toUpperCase();
const circl = $json.circl || {};
const summary = circl.summary || circl.descriptions?.[0]?.value || circl.message || 'No CIRCL data (offline or unknown CVE)';
const cvss = circl.cvss || circl.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 'n/a';
const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${cve}</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7ecf3}
h1{color:#5eead4}.card{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}</style></head>
<body><h1>LAB CVE Info</h1>
<div class="card"><p><strong>${cve}</strong></p><p>CVSS: ${cvss}</p><p>${summary}</p>
<p>Source: cve.circl.lu (no API key) · fallback stub if unreachable</p></div>
</body></html>`;
return [{ json: { cve, circl, summary, cvss, html, type: 'cve' } }];
"""

PARSE_QUERY_CODE = r"""
const q = $json.query || {};
const body = $json.body || {};
const ip = (q.ip || body.ip || '').toString().trim();
const domain = (q.domain || body.domain || '').toString().trim();
const hash = (q.hash || body.hash || '').toString().trim();
const cve = (q.cve || body.cve || '').toString().trim();
let type = 'unknown';
if (ip) type = 'ip';
else if (domain) type = 'domain';
else if (hash) type = 'hash';
else if (cve) type = 'cve';
return [{ json: { type, ip, domain, hash, cve, query: q } }];
"""

UNKNOWN_HTML_CODE = r"""
const html = `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f1419;color:#e7ecf3;padding:2rem">
<h1>LAB TI Dispatcher</h1>
<p>Provide one query param: <code>?ip=</code> <code>?domain=</code> <code>?hash=</code> <code>?cve=</code></p>
<p>Example: <a style="color:#7dd3fc" href="/webhook/lab-reputation?ip=8.8.8.8">/webhook/lab-reputation?ip=8.8.8.8</a></p>
</body></html>`;
return [{ json: { html, type: 'unknown' } }];
"""


def build_dispatcher():
    nodes = [
        node(
            "wh1",
            "Webhook",
            "n8n-nodes-base.webhook",
            {
                "httpMethod": "GET",
                "path": "lab-reputation",
                "responseMode": "responseNode",
                "options": {},
            },
            [-800, 300],
            typeVersion=2,
            webhookId="lab-reputation",
        ),
        node("parse1", "Parse Query", "n8n-nodes-base.code", {"jsCode": PARSE_QUERY_CODE}, [-560, 300], typeVersion=2),
        node(
            "sw1",
            "Switch Type",
            "n8n-nodes-base.switch",
            {
                "rules": {
                    "values": [
                        {"conditions": {"conditions": [{"leftValue": "={{ $json.type }}", "rightValue": "ip", "operator": {"type": "string", "operation": "equals"}}]}},
                        {"conditions": {"conditions": [{"leftValue": "={{ $json.type }}", "rightValue": "domain", "operator": {"type": "string", "operation": "equals"}}]}},
                        {"conditions": {"conditions": [{"leftValue": "={{ $json.type }}", "rightValue": "hash", "operator": {"type": "string", "operation": "equals"}}]}},
                        {"conditions": {"conditions": [{"leftValue": "={{ $json.type }}", "rightValue": "cve", "operator": {"type": "string", "operation": "equals"}}]}},
                    ]
                },
                "options": {},
            },
            [-320, 300],
            typeVersion=3,
        ),
        # IP branch
        node(
            "http_geo",
            "ip-api Geo",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=http://ip-api.com/json/{{ $json.ip }}?fields=status,message,country,countryCode,city,isp,org,query",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-80, 0],
            typeVersion=4.2,
        ),
        node(
            "merge_ip",
            "Merge IP Context",
            "n8n-nodes-base.code",
            {
                "jsCode": "const prev=$('Parse Query').item.json; return [{json:{...prev, geo:$json}}];"
            },
            [140, 0],
            typeVersion=2,
        ),
        node("ip_html", "Build IP HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_IP_CODE}, [360, 0], typeVersion=2),
        # Domain
        node(
            "http_dns",
            "Google DNS",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=https://dns.google/resolve?name={{ $json.domain }}&type=A",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-80, 200],
            typeVersion=4.2,
        ),
        node(
            "merge_dom",
            "Merge Domain Context",
            "n8n-nodes-base.code",
            {"jsCode": "const prev=$('Parse Query').item.json; return [{json:{...prev, dns:$json}}];"},
            [140, 200],
            typeVersion=2,
        ),
        node("dom_html", "Build Domain HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_DOMAIN_CODE}, [360, 200], typeVersion=2),
        # Hash
        node("hash_html", "Build Hash HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_HASH_CODE}, [-80, 400], typeVersion=2),
        # CVE
        node(
            "http_cve",
            "CIRCL CVE",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=https://cve.circl.lu/api/cve/{{ $json.cve }}",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-80, 560],
            typeVersion=4.2,
        ),
        node(
            "merge_cve",
            "Merge CVE Context",
            "n8n-nodes-base.code",
            {"jsCode": "const prev=$('Parse Query').item.json; return [{json:{...prev, circl:$json}}];"},
            [140, 560],
            typeVersion=2,
        ),
        node("cve_html", "Build CVE HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_CVE_CODE}, [360, 560], typeVersion=2),
        node("unk_html", "Unknown Help", "n8n-nodes-base.code", {"jsCode": UNKNOWN_HTML_CODE}, [-80, 720], typeVersion=2),
        node(
            "respond",
            "Respond HTML",
            "n8n-nodes-base.respondToWebhook",
            {
                "respondWith": "text",
                "responseBody": "={{ $json.html }}",
                "options": {"responseHeaders": {"entries": [{"name": "Content-Type", "value": "text/html; charset=utf-8"}]}},
            },
            [640, 300],
            typeVersion=1.1,
        ),
    ]
    connections = {
        "Webhook": {"main": [[{"node": "Parse Query", "type": "main", "index": 0}]]},
        "Parse Query": {"main": [[{"node": "Switch Type", "type": "main", "index": 0}]]},
        "Switch Type": {
            "main": [
                [{"node": "ip-api Geo", "type": "main", "index": 0}],
                [{"node": "Google DNS", "type": "main", "index": 0}],
                [{"node": "Build Hash HTML", "type": "main", "index": 0}],
                [{"node": "CIRCL CVE", "type": "main", "index": 0}],
                [{"node": "Unknown Help", "type": "main", "index": 0}],
            ]
        },
        "ip-api Geo": {"main": [[{"node": "Merge IP Context", "type": "main", "index": 0}]]},
        "Merge IP Context": {"main": [[{"node": "Build IP HTML", "type": "main", "index": 0}]]},
        "Build IP HTML": {"main": [[{"node": "Respond HTML", "type": "main", "index": 0}]]},
        "Google DNS": {"main": [[{"node": "Merge Domain Context", "type": "main", "index": 0}]]},
        "Merge Domain Context": {"main": [[{"node": "Build Domain HTML", "type": "main", "index": 0}]]},
        "Build Domain HTML": {"main": [[{"node": "Respond HTML", "type": "main", "index": 0}]]},
        "Build Hash HTML": {"main": [[{"node": "Respond HTML", "type": "main", "index": 0}]]},
        "CIRCL CVE": {"main": [[{"node": "Merge CVE Context", "type": "main", "index": 0}]]},
        "Merge CVE Context": {"main": [[{"node": "Build CVE HTML", "type": "main", "index": 0}]]},
        "Build CVE HTML": {"main": [[{"node": "Respond HTML", "type": "main", "index": 0}]]},
        "Unknown Help": {"main": [[{"node": "Respond HTML", "type": "main", "index": 0}]]},
    }
    return {
        "name": "LAB - TI Dispatcher",
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [{"name": "lab-soc"}],
    }


def sub_workflow(name, input_field, build_nodes_fn):
    """Standalone Execute Workflow Trigger modules for portfolio / optional linking."""
    nodes, connections = build_nodes_fn()
    return {
        "name": name,
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [{"name": "lab-soc"}],
    }


def build_ip_module():
    nodes = [
        node(
            "t1",
            "When Executed by Another Workflow",
            "n8n-nodes-base.executeWorkflowTrigger",
            {"workflowInputs": {"values": [{"name": "ip"}]}},
            [-600, 0],
            typeVersion=1.1,
        ),
        node(
            "http_geo",
            "ip-api Geo",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=http://ip-api.com/json/{{ $json.ip }}?fields=status,message,country,countryCode,city,isp,org,query",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-360, 0],
            typeVersion=4.2,
        ),
        node(
            "merge",
            "Merge",
            "n8n-nodes-base.code",
            {"jsCode": "const ip=$('When Executed by Another Workflow').item.json.ip; return [{json:{ip, geo:$json}}];"},
            [-120, 0],
            typeVersion=2,
        ),
        node("html", "Build IP HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_IP_CODE}, [120, 0], typeVersion=2),
    ]
    connections = {
        "When Executed by Another Workflow": {"main": [[{"node": "ip-api Geo", "type": "main", "index": 0}]]},
        "ip-api Geo": {"main": [[{"node": "Merge", "type": "main", "index": 0}]]},
        "Merge": {"main": [[{"node": "Build IP HTML", "type": "main", "index": 0}]]},
    }
    return nodes, connections


def build_domain_module():
    nodes = [
        node(
            "t1",
            "When Executed by Another Workflow",
            "n8n-nodes-base.executeWorkflowTrigger",
            {"workflowInputs": {"values": [{"name": "domain"}]}},
            [-600, 0],
            typeVersion=1.1,
        ),
        node(
            "http_dns",
            "Google DNS",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=https://dns.google/resolve?name={{ $json.domain }}&type=A",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-360, 0],
            typeVersion=4.2,
        ),
        node(
            "merge",
            "Merge",
            "n8n-nodes-base.code",
            {"jsCode": "const domain=$('When Executed by Another Workflow').item.json.domain; return [{json:{domain, dns:$json}}];"},
            [-120, 0],
            typeVersion=2,
        ),
        node("html", "Build Domain HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_DOMAIN_CODE}, [120, 0], typeVersion=2),
    ]
    connections = {
        "When Executed by Another Workflow": {"main": [[{"node": "Google DNS", "type": "main", "index": 0}]]},
        "Google DNS": {"main": [[{"node": "Merge", "type": "main", "index": 0}]]},
        "Merge": {"main": [[{"node": "Build Domain HTML", "type": "main", "index": 0}]]},
    }
    return nodes, connections


def build_hash_module():
    nodes = [
        node(
            "t1",
            "When Executed by Another Workflow",
            "n8n-nodes-base.executeWorkflowTrigger",
            {"workflowInputs": {"values": [{"name": "hash"}]}},
            [-400, 0],
            typeVersion=1.1,
        ),
        node("html", "Build Hash HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_HASH_CODE}, [-100, 0], typeVersion=2),
    ]
    connections = {
        "When Executed by Another Workflow": {"main": [[{"node": "Build Hash HTML", "type": "main", "index": 0}]]},
    }
    return nodes, connections


def build_cve_module():
    nodes = [
        node(
            "t1",
            "When Executed by Another Workflow",
            "n8n-nodes-base.executeWorkflowTrigger",
            {"workflowInputs": {"values": [{"name": "cve"}]}},
            [-600, 0],
            typeVersion=1.1,
        ),
        node(
            "http_cve",
            "CIRCL CVE",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=https://cve.circl.lu/api/cve/{{ $json.cve }}",
                "options": {"response": {"response": {"neverError": True}}},
            },
            [-360, 0],
            typeVersion=4.2,
        ),
        node(
            "merge",
            "Merge",
            "n8n-nodes-base.code",
            {"jsCode": "const cve=$('When Executed by Another Workflow').item.json.cve; return [{json:{cve, circl:$json}}];"},
            [-120, 0],
            typeVersion=2,
        ),
        node("html", "Build CVE HTML", "n8n-nodes-base.code", {"jsCode": ENRICH_CVE_CODE}, [120, 0], typeVersion=2),
    ]
    connections = {
        "When Executed by Another Workflow": {"main": [[{"node": "CIRCL CVE", "type": "main", "index": 0}]]},
        "CIRCL CVE": {"main": [[{"node": "Merge", "type": "main", "index": 0}]]},
        "Merge": {"main": [[{"node": "Build CVE HTML", "type": "main", "index": 0}]]},
    }
    return nodes, connections


POLLER_CODE = r"""
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');

const STATE = '/data/n8n-state/seen-alerts.json';
const TRIAGE = '/data/alerts-triage';
const REPORTS = '/data/soc-reports';
const WINLOGS = '/data/winlogs';
const BRIDGE = '/data/n8n-state/warning-plus.jsonl';

for (const d of [path.dirname(STATE), TRIAGE, REPORTS]) {
  try { fs.mkdirSync(d, { recursive: true }); } catch (e) {}
}

let seen = {};
try { seen = JSON.parse(fs.readFileSync(STATE, 'utf8') || '{}'); } catch (e) { seen = {}; }

const warnLevels = new Set(['avviso','warning','errore','error','critico','critical']);
const events = [];

function pushEvent(result) {
  if (!result || typeof result !== 'object') return;
  const level = (result.Level || result.level || '').toString();
  if (!warnLevels.has(level.toLowerCase())) return;
  events.push(result);
}

if (fs.existsSync(BRIDGE)) {
  const text = fs.readFileSync(BRIDGE, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { pushEvent(JSON.parse(line)); } catch (e) {}
  }
}

if (!events.length && fs.existsSync(WINLOGS)) {
  const files = fs.readdirSync(WINLOGS).filter(f => f.endsWith('.json')).slice(-20);
  for (const f of files) {
    const text = fs.readFileSync(path.join(WINLOGS, f), 'utf8');
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try { pushEvent(JSON.parse(line)); } catch (e) {}
    }
  }
}

const items = [];
for (const result of events.slice(0, 30)) {
  const id = result.Id ?? result.id ?? 'na';
  const timeCreated = result.TimeCreated || result.time_created || result._time || '';
  const logName = result.LogName || result.log_name || 'Unknown';
  const level = result.Level || result.level || '';
  const message = (result.Message || result.message || '').toString();
  const alertId = crypto.createHash('sha1').update(`${id}|${timeCreated}|${logName}`).digest('hex').slice(0, 16);
  const alert_id = `auto-${alertId}`;
  if (seen[alert_id]) continue;
  seen[alert_id] = new Date().toISOString();

  const ips = [...message.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g)].map(m => m[0]);
  const cves = [...message.matchAll(/CVE-\d{4}-\d{4,}/gi)].map(m => m[0].toUpperCase());
  const ip = ips.find(x => !x.startsWith('127.') && !x.startsWith('0.')) || ips[0] || '8.8.8.8';
  const cve = cves[0] || '';

  const triage = {
    alert_id,
    status: 'open',
    source_id: id,
    log_name: logName,
    level,
    time_created: timeCreated,
    message: message.slice(0, 2000),
    opened_at: new Date().toISOString(),
    closed_at: null,
    owner: null,
    iocs: { ip, cve, ips: ips.slice(0, 5) },
    detection_source: 'winlogs_or_splunk_bridge'
  };
  fs.writeFileSync(path.join(TRIAGE, `open-${alert_id}.json`), JSON.stringify(triage));
  items.push({ json: triage });
}

fs.writeFileSync(STATE, JSON.stringify(seen, null, 2));
if (!items.length) {
  return [{ json: { skipped: true, reason: 'no_new_alerts', scanned: events.length } }];
}
return items;
"""

REPORT_CODE = r"""
const fs = require('fs');
const path = require('path');
const alert = $('Process New Alerts').item.json;
if (alert.skipped) {
  return [{ json: { skipped: true } }];
}
const enrichHtml = $json.html || ($json.data || '');
const ai = $json.ai_summary || $json.response || 'AI summary skipped (Ollama offline or model missing).';
const report = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>SOC Report ${alert.alert_id}</title>
<style>body{font-family:Segoe UI,system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;background:#0f1419;color:#e7ecf3}
h1{color:#5eead4}.card{background:#1e293b;border-radius:8px;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap}</style></head>
<body>
<h1>SOC Automation Report</h1>
<div class="card"><h2>Alert</h2>
<p><strong>${alert.alert_id}</strong> · ${alert.log_name} · Id ${alert.source_id} · ${alert.level}</p>
<pre>${(alert.message||'').slice(0,1500)}</pre></div>
<div class="card"><h2>AI triage (Ollama)</h2><pre>${typeof ai === 'string' ? ai : JSON.stringify(ai)}</pre></div>
<div class="card"><h2>Enrichment</h2>${enrichHtml || '<p>No IOC enrichment for this event.</p>'}</div>
</body></html>`;
const out = path.join('/data/soc-reports', `${alert.alert_id}.html`);
fs.writeFileSync(out, report);
return [{ json: { ...alert, report_path: out, ai_summary: ai } }];
"""

CLOSE_CODE = r"""
const fs = require('fs');
const path = require('path');
const body = $json.body || $json;
const alert_id = (body.alert_id || '').toString().trim();
const owner = (body.owner || 'demo').toString();
if (!alert_id) {
  return [{ json: { ok: false, error: 'alert_id required' } }];
}
const TRIAGE = '/data/alerts-triage';
fs.mkdirSync(TRIAGE, { recursive: true });
const now = new Date().toISOString();
const row = {
  alert_id,
  status: 'closed',
  closed_at: now,
  owner,
  opened_at: null,
  message: 'Closed via LAB - Close Alert webhook'
};
const file = path.join(TRIAGE, `close-${alert_id}-${Date.now()}.json`);
fs.writeFileSync(file, JSON.stringify(row));
return [{ json: { ok: true, file, ...row } }];
"""


def build_poller():
    nodes = [
        node(
            "sched",
            "Every 5 Minutes",
            "n8n-nodes-base.scheduleTrigger",
            {"rule": {"interval": [{"field": "minutes", "minutesInterval": 5}]}},
            [-700, 200],
            typeVersion=1.2,
        ),
        node(
            "note",
            "Detection Note",
            "n8n-nodes-base.code",
            {
                "jsCode": (
                    "// Splunk Free disables remote REST login. Detection reads:\n"
                    "// 1) /data/n8n-state/warning-plus.jsonl (host: splunk-warning-export.ps1)\n"
                    "// 2) fallback /data/winlogs JSON (same files Splunk indexes)\n"
                    "return [{ json: { ok: true } }];"
                )
            },
            [-480, 200],
            typeVersion=2,
        ),
        node("proc", "Process New Alerts", "n8n-nodes-base.code", {"jsCode": POLLER_CODE}, [-260, 200], typeVersion=2),
        node(
            "ifnew",
            "Has New Alert?",
            "n8n-nodes-base.if",
            {
                "conditions": {
                    "conditions": [
                        {
                            "leftValue": "={{ $json.skipped }}",
                            "rightValue": True,
                            "operator": {"type": "boolean", "operation": "notEquals"},
                        }
                    ]
                }
            },
            [-40, 200],
            typeVersion=2,
        ),
        node(
            "enrich",
            "Enrich IP via Dispatcher",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=http://127.0.0.1:5678/webhook/lab-reputation?ip={{ $json.iocs.ip || '8.8.8.8' }}",
                "options": {
                    "response": {"response": {"neverError": True, "responseFormat": "text"}},
                },
            },
            [200, 80],
            typeVersion=4.2,
        ),
        node(
            "ai_prep",
            "Prep Ollama Prompt",
            "n8n-nodes-base.code",
            {
                "jsCode": """
const a = $('Process New Alerts').item.json;
const enrich = $json.data || $json;
const prompt = `Sei un analista SOC. Riassumi in italiano in 4 bullet max questo alert Windows e suggerisci next steps.\\nLog: ${a.log_name} Id=${a.source_id} Level=${a.level}\\nMsg: ${(a.message||'').slice(0,800)}`;
return [{ json: { ...a, enrich_html: typeof enrich === 'string' ? enrich : '', prompt } }];
"""
            },
            [420, 80],
            typeVersion=2,
        ),
        node(
            "ollama",
            "Ollama Summary",
            "n8n-nodes-base.httpRequest",
            {
                "method": "POST",
                "url": "={{ ($env.OLLAMA_URL || 'http://lab_ollama:11434') + '/api/generate' }}",
                "sendBody": True,
                "specifyBody": "json",
                "jsonBody": "={{ JSON.stringify({ model: $env.OLLAMA_MODEL || 'llama3.2:1b', prompt: $json.prompt, stream: false }) }}",
                "options": {
                    "timeout": 120000,
                    "response": {"response": {"neverError": True}},
                },
            },
            [640, 80],
            typeVersion=4.2,
        ),
        node(
            "merge_ai",
            "Merge AI + Enrich",
            "n8n-nodes-base.code",
            {
                "jsCode": """
const prep = $('Prep Ollama Prompt').item.json;
const ai = $json.response || $json.error || 'AI summary skipped (Ollama offline or model missing).';
return [{ json: { html: prep.enrich_html, ai_summary: ai, alert_id: prep.alert_id } }];
"""
            },
            [860, 80],
            typeVersion=2,
        ),
        node("report", "Write SOC Report", "n8n-nodes-base.code", {"jsCode": REPORT_CODE}, [1080, 80], typeVersion=2),
    ]
    connections = {
        "Every 5 Minutes": {"main": [[{"node": "Detection Note", "type": "main", "index": 0}]]},
        "Detection Note": {"main": [[{"node": "Process New Alerts", "type": "main", "index": 0}]]},
        "Process New Alerts": {"main": [[{"node": "Has New Alert?", "type": "main", "index": 0}]]},
        "Has New Alert?": {
            "main": [
                [{"node": "Enrich IP via Dispatcher", "type": "main", "index": 0}],
                [],
            ]
        },
        "Enrich IP via Dispatcher": {"main": [[{"node": "Prep Ollama Prompt", "type": "main", "index": 0}]]},
        "Prep Ollama Prompt": {"main": [[{"node": "Ollama Summary", "type": "main", "index": 0}]]},
        "Ollama Summary": {"main": [[{"node": "Merge AI + Enrich", "type": "main", "index": 0}]]},
        "Merge AI + Enrich": {"main": [[{"node": "Write SOC Report", "type": "main", "index": 0}]]},
    }
    return {
        "name": "LAB - Splunk Warning Poller",
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [{"name": "lab-soc"}],
    }


def build_close():
    nodes = [
        node(
            "wh",
            "Webhook Close",
            "n8n-nodes-base.webhook",
            {
                "httpMethod": "POST",
                "path": "lab-close",
                "responseMode": "responseNode",
                "options": {},
            },
            [-400, 0],
            typeVersion=2,
            webhookId="lab-close",
        ),
        node("code", "Write Closed Event", "n8n-nodes-base.code", {"jsCode": CLOSE_CODE}, [-160, 0], typeVersion=2),
        node(
            "resp",
            "Respond JSON",
            "n8n-nodes-base.respondToWebhook",
            {
                "respondWith": "json",
                "responseBody": "={{ $json }}",
                "options": {},
            },
            [80, 0],
            typeVersion=1.1,
        ),
    ]
    connections = {
        "Webhook Close": {"main": [[{"node": "Write Closed Event", "type": "main", "index": 0}]]},
        "Write Closed Event": {"main": [[{"node": "Respond JSON", "type": "main", "index": 0}]]},
    }
    return {
        "name": "LAB - Close Alert",
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [{"name": "lab-soc"}],
    }


def build_manual_demo():
    """Manual trigger that writes a sample open alert + calls enrichment path without Splunk."""
    code = r"""
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const TRIAGE = '/data/alerts-triage';
const REPORTS = '/data/soc-reports';
fs.mkdirSync(TRIAGE, { recursive: true });
fs.mkdirSync(REPORTS, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g,'-');
const alert_id = `demo-${stamp.slice(0,19)}`;
const triage = {
  alert_id,
  status: 'open',
  source_id: 41,
  log_name: 'System',
  level: 'Errore',
  time_created: new Date().toISOString(),
  message: 'Demo Kernel-Power unexpected shutdown. Related host 8.8.8.8 CVE-2021-44228',
  opened_at: new Date().toISOString(),
  closed_at: null,
  owner: null,
  iocs: { ip: '8.8.8.8', cve: 'CVE-2021-44228' }
};
fs.writeFileSync(path.join(TRIAGE, `open-${alert_id}.json`), JSON.stringify(triage));
return [{ json: triage }];
"""
    nodes = [
        node("manual", "Manual Trigger", "n8n-nodes-base.manualTrigger", {}, [-500, 0], typeVersion=1),
        node("sample", "Create Sample Open", "n8n-nodes-base.code", {"jsCode": code}, [-280, 0], typeVersion=2),
        node(
            "enrich",
            "Call Dispatcher IP",
            "n8n-nodes-base.httpRequest",
            {
                "url": "=http://127.0.0.1:5678/webhook/lab-reputation?ip={{ $json.iocs.ip }}",
                "options": {"response": {"response": {"neverError": True, "responseFormat": "text"}}},
            },
            [-40, 0],
            typeVersion=4.2,
        ),
        node(
            "report",
            "Write Demo Report",
            "n8n-nodes-base.code",
            {
                "jsCode": r"""
const fs = require('fs');
const path = require('path');
const a = $('Create Sample Open').item.json;
const html = $json.data || $json;
const report = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${a.alert_id}</title></head>
<body style="font-family:sans-serif;background:#0f1419;color:#e7ecf3;padding:2rem">
<h1>Demo SOC Report</h1><p>${a.alert_id}</p><pre>${a.message}</pre><hr/>${html}</body></html>`;
const out = path.join('/data/soc-reports', `${a.alert_id}.html`);
fs.writeFileSync(out, report);
return [{ json: { ...a, report_path: out } }];
"""
            },
            [200, 0],
            typeVersion=2,
        ),
    ]
    connections = {
        "Manual Trigger": {"main": [[{"node": "Create Sample Open", "type": "main", "index": 0}]]},
        "Create Sample Open": {"main": [[{"node": "Call Dispatcher IP", "type": "main", "index": 0}]]},
        "Call Dispatcher IP": {"main": [[{"node": "Write Demo Report", "type": "main", "index": 0}]]},
    }
    return {
        "name": "LAB - Manual Demo Pipeline",
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"executionOrder": "v1"},
        "meta": {"templateCredsSetupCompleted": True},
        "tags": [{"name": "lab-soc"}],
    }


def main():
    save("LAB-TI-Dispatcher.json", build_dispatcher())
    save("LAB-IP-Reputation.json", sub_workflow("LAB - IP Reputation", "ip", build_ip_module))
    save("LAB-Domain-Reputation.json", sub_workflow("LAB - Domain Reputation", "domain", build_domain_module))
    save("LAB-Hash-Reputation.json", sub_workflow("LAB - Hash Reputation", "hash", build_hash_module))
    save("LAB-CVE-Info.json", sub_workflow("LAB - CVE Info", "cve", build_cve_module))
    save("LAB-Splunk-Warning-Poller.json", build_poller())
    save("LAB-Close-Alert.json", build_close())
    save("LAB-Manual-Demo-Pipeline.json", build_manual_demo())
    print("Done.")


if __name__ == "__main__":
    main()
