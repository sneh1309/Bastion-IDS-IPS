# Bastion — IDS/IPS Management Console

A lightweight intrusion detection & prevention system you can run yourself:
**Suricata** does the packet inspection, the **Bastion agent** turns its alerts
into an API and applies real firewall blocks, and the **Bastion console** is the
single app you manage everything from.

```
   Internet
      │
      ▼
 ┌─────────────┐     eve.json      ┌──────────────┐    HTTP API     ┌─────────────┐
 │  SENSOR     │  ───────────────► │ bastion_agent │ ◄────────────► │   CONSOLE   │
 │ (Suricata)  │                   │  (per sensor) │                 │ (index.html)│
 │  + nftables │  ◄─── blocks ──── │               │                 │             │
 └─────────────┘                   └──────────────┘                 └─────────────┘
```

## Features

- **Live alert feed** — severity-ranked Suricata alerts with source/destination detail
- **IDS / IPS modes** — detect-only, or auto-block high-severity attackers via nftables
- **Sensor management** — monitor multiple deployments from one console
- **Rule categories** — enable/disable Emerging Threats-style rulesets
- **Blocklist control** — block or unblock any source IP with one click
- **AI alert analysis** — per-alert plain-language explanation and recommended actions
  (runs when opened inside Claude; console works everywhere without it)

The console ships with a simulated feed (marked **DEMO DATA**) so it works
standalone in any browser. Connecting it to a real sensor is a one-function
change — see the guide.

## Quick start

**Try the console:** open `console/index.html` in a browser.

**Deploy a real sensor** (Ubuntu/Debian, ~30 min):

```bash
sudo apt install -y suricata
sudo suricata-update
sudo systemctl enable --now suricata

pip install flask
sudo python3 agent/bastion_agent.py --eve /var/log/suricata/eve.json --mode ids
```

Then follow [`docs/SETUP-and-BUSINESS-GUIDE.md`](docs/SETUP-and-BUSINESS-GUIDE.md)
to wire the console to the agent's API, tune rules, and (only when trusted)
switch to IPS mode.

## Repository layout

| Path | What it is |
|---|---|
| `console/index.html` | The management console — single-file web app |
| `agent/bastion_agent.py` | Sensor agent: tails eve.json, serves the API, applies nftables blocks |
| `docs/SETUP-and-BUSINESS-GUIDE.md` | Deployment walkthrough + honest notes on running this as a service |

## Safety notes

- Always start in **IDS mode**; run inline IPS only after a week of tuning.
- IPS blocking uses a dedicated `bastion` nftables table so it never disturbs
  your existing firewall rules.
- This tool is for **defending networks you own or are authorized to protect**.

## License

MIT — see [LICENSE](LICENSE). Suricata itself is GPLv2 and installed separately;
this project contains no Suricata code.
