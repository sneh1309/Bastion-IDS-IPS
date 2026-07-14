# Bastion — Setup & Business Guide

An IDS/IPS product you can run for yourself and sell to others. This guide covers
**how it fits together, how to deploy it for real, and honest ways to make money from it.**

---

## 1. What you actually have

Three pieces, and it's important to understand the division of labour:

| Piece | File | Job |
|---|---|---|
| **Detection engine** | *Suricata* (not written by you — you install it) | Inspects packets, matches threats, decides detect vs. block |
| **Sensor agent** | `bastion_agent.py` | Reads Suricata's output, exposes an API, applies firewall blocks |
| **Management console** | `bastion-console.html` | The "one app" — view alerts, manage sensors/rules, block/unblock, AI analysis |

**Key point:** you are not competing with Suricata — you are *packaging* it. Suricata is the
best open-source detection engine in the world and it's free. Trying to rewrite it would take
years and lose. The product — and the money — is in the **management, curation, and convenience**
layer on top. That's the same model Firewalla, Meraki, and most commercial IDS/IPS boxes use.

```
   Internet
      │
      ▼
 ┌─────────────┐     eve.json      ┌──────────────┐    HTTPS API    ┌─────────────┐
 │  SENSOR     │  ───────────────► │ bastion_agent │ ◄────────────► │   CONSOLE   │
 │ (Suricata)  │                   │  (per sensor) │                 │ (your app)  │
 │  + nftables │  ◄─── blocks ──── │               │                 │  you/clients│
 └─────────────┘                   └──────────────┘                 └─────────────┘
   watches traffic                  parses + controls               manage everything
```

---

## 2. IDS vs. IPS — the one distinction to get right

- **IDS (detection):** the sensor watches a *copy* of traffic (a mirror/SPAN port) and raises
  alerts. It cannot break your network because it isn't in the path. Safest starting mode.
- **IPS (prevention):** the sensor sits *inline* — traffic flows through it — so it can actually
  drop attacks. More powerful, but if it fails or misconfigures, it can take the network down.

**Advice:** always deploy in IDS mode first, watch it for a week to tune out false positives,
*then* switch to IPS. The console's IDS/IPS toggle mirrors this.

---

## 3. Deploy a real sensor (30 minutes)

You need a machine on the network: a Raspberry Pi 4/5, an Intel mini-PC (e.g. an N100 box),
or a VM. Ubuntu/Debian assumed below.

```bash
# 1. Install Suricata
sudo apt update && sudo apt install -y suricata

# 2. Pull the free Emerging Threats ruleset (the same categories shown in the console)
sudo suricata-update
sudo suricata-update list-sources

# 3. Point Suricata at your network interface and confirm eve.json logging is on
#    (it is by default) in /etc/suricata/suricata.yaml:  af-packet: - interface: eth0
sudo systemctl enable --now suricata

# 4. Install and run the agent
pip install flask
sudo python3 bastion_agent.py --eve /var/log/suricata/eve.json --mode ids
```

The agent now serves:
- `GET  /api/alerts` — recent alerts + top talkers
- `GET  /api/blocked` — current blocklist
- `POST /api/block` `{ "ip": "1.2.3.4" }`
- `POST /api/unblock` `{ "ip": "1.2.3.4" }`
- `POST /api/mode` `{ "mode": "ips" }`

> **IPS mode** uses `nftables` in a dedicated `bastion` table, so it never disturbs your other
> firewall rules. Blocks are real kernel-level drops. Test in IDS first.

---

## 4. Connect the console to real data

The console ships with a simulated feed so it's alive out of the box. To make it real, replace
the demo generator with a poll of your agent. In `bastion-console.html`, swap the `tick()` loop:

```js
async function tick() {
  const res  = await fetch("https://your-sensor:8787/api/alerts?limit=40");
  const data = await res.json();
  S.alerts = data.alerts;         // real Suricata alerts
  renderFeed(); renderStats(); renderKPIs();
}
setInterval(tick, 3000);
```

Wire the Block/Unblock buttons and the IDS/IPS toggle to `POST /api/block` etc. the same way.
That's the entire "make it real" step — the UI, scoring, and workflow are already built.

**For multiple sensors / customers:** put a small cloud service between the console and the
agents (each agent pushes to it over an authenticated tunnel), and give each customer a scoped
login. That central service is what you actually sell access to.

---

## 5. Making money — honestly

The software layer is largely commoditized (Suricata is free; pfSense/OPNsense/Firewalla exist).
So **don't try to sell the code.** Sell the things that are genuinely hard and that people will
pay to avoid doing themselves. Realistic models, roughly easiest → most lucrative:

**A. Managed monitoring service (best fit for one person starting out).**
You run and watch the sensors; the customer pays a monthly fee for peace of mind. Small
businesses — dental clinics, law offices, retail — have no IT staff and real compliance pressure.
Typical pricing: **$50–250/site/month.** Ten sites = a real income. This is where the money is,
because you're selling *your attention and expertise*, not a download.

**B. Hardware appliance.**
Pre-load a mini-PC with Suricata + the agent, ship it, charge for the box plus a subscription.
Higher trust and stickier, but you take on inventory, shipping, and RMA.

**C. Hosted SaaS console.**
Charge per sensor/seat for the cloud console + curated rules + AI analysis. Recurring revenue,
but you're now competing with funded companies and carry uptime/security obligations.

**D. Support & setup tiers.**
Even a free/open tool can charge for installation, tuning, incident response retainers, and SLAs.

**Suggested path:** start with **(A) managed service for 2–3 local businesses.** It needs no
funding, validates that people will pay, and every model above builds on that base.

### Be clear-eyed about the hard parts

- **Trust is the product.** People are handing you their security. Reputation, references, and
  a clean track record matter more than features. Start with clients who already know you.
- **Support is the real cost.** Alerts fire at 2 a.m. Budget for it or set explicit SLAs.
- **Liability is real.** If you sell "protection" and a client is breached, expect scrutiny.
  Use a written contract that scopes what you do and don't guarantee, carry
  professional/cyber liability insurance, and never promise 100% prevention (no one can).
- **Licensing:** Suricata is GPLv2 and Emerging Threats has an open ruleset — fine to build a
  commercial service around, but read the license terms and keep your own code separate.
- **Regulation:** if clients handle health, payment, or personal data (HIPAA, PCI, PIPEDA in
  Canada), your service becomes part of *their* compliance story. That's a selling point, but
  learn the basics before you promise it.

None of this is meant to discourage you — it's the same checklist every managed security
provider works through. The demand is real and growing; the winners are the ones who are
trustworthy, responsive, and honest about limits.

---

## 6. Sensible next steps

1. Stand up one sensor on your **own** network in IDS mode. Live with it for a week.
2. Connect the console to it (Section 4) and tune out noisy rules.
3. Switch that sensor to IPS once you trust it.
4. Offer to monitor **one** friendly local business for a low intro rate. Learn from a real site.
5. Only then decide between the managed / appliance / SaaS models above.

Build trust before you build scale.
