Python Windows EVTX Log Analysis & Alerting
Overview

This project converts Windows Event Log (.evtx) files into newline‑delimited JSON and runs a simple detection for repeated failed logon events. The pipeline produces structured alerts and can optionally enrich them with AI‑generated triage details using a local large language model via Ollama.

Motivation

During security monitoring, analysts often need to parse host logs, detect suspicious patterns and prioritise events. This project was created as a learning exercise to parse raw Windows event logs, implement a detection rule for a common attack technique (credential stuffing / brute force) and experiment with using generative AI to assign severity and recommended actions. It is not a full SIEM replacement but demonstrates a security engineering workflow end‑to‑end.

Features

EVTX → JSONL conversion: uses the python‑evtx and xmltodict libraries to parse Windows .evtx files and write each record as a JSON document.

Brute‑force detection: analyses Event ID 4625 (failed logon) events, grouping by source IP and username, and flags any pair that exceeds a configurable threshold within a time window.

Alert output: writes each alert as a JSON line to out/alerts.jsonl for easy downstream processing.

AI triage integration: calls a local language model via Ollama to estimate severity, confidence, MITRE technique, explanation and recommended remediation steps. The model and server URL can be overridden via environment variables.

Repository structure
File/Dir	Purpose
main.py	Orchestrates the pipeline: parses EVTX if needed, runs detectors, calls AI triage and writes enriched alerts.
log_parser.py	Defines evtx_to_jsonl, which converts an EVTX file into newline‑delimited JSON using python‑evtx and xmltodict.
detectors.py	Implements detect_bruteforce_failed_4625, which groups failed logon events by IP and username and flags bursts above a threshold.
alert.py	Contains a helper to append alerts to a JSONL file.
ai_call.py	Sends an alert to a local LLM via the Ollama API and returns AI‑generated triage information.
data/	Expected location for EVTX sample files.
out/	Output directory for security.jsonl, alerts.jsonl and enriched_alerts.jsonl.
requirements.txt	Python package dependencies (python‑evtx, xmltodict, requests).
Setup

This project requires Python 3.10+ and a working installation of Ollama if you plan to use the AI features.

Clone or download this repository.

Create and activate a virtual environment:

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate


Install dependencies:

pip install -r requirements.txt


Place a Windows .evtx file into the data/ directory and update EVTX_IN in main.py to match its filename.

Optional: set up Ollama

If you wish to use the AI triage feature, install and run Ollama, then pull a model such as mistral. The ai_call.py module defaults to http://localhost:11434 and the mistral model, but you can override these via environment variables:

export OLLAMA_URL=http://localhost:11434
export OLLAMA_MODEL=mistral
ollama serve  # start the Ollama server

Usage

Run the pipeline:

python main.py


If the specified .jsonl output file does not exist, the script first parses the EVTX file into JSONL.

It then runs the brute‑force detector with configurable window_seconds and threshold parameters.

Alerts are enriched with AI triage data where available; if the AI call fails, the original alert is preserved.

The resulting enriched alerts are written to out/enriched_alerts.jsonl.