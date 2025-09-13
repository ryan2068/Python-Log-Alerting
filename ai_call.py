import os
import requests
import json

# URL and model can be overridden with environment variables if needed
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
MODEL = os.getenv("OLLAMA_MODEL", "mistral")

def ai_triage(alert: dict) -> dict:
    """
    Enrich a basic alert dict with AI‑generated severity, confidence, MITRE ID,
    explanation, and recommended actions.

    The returned dict has keys:
      - severity: one of "low","medium","high","critical"
      - confidence: float 0–1
      - mitre: a technique ID string or null
      - explanation: short plain‑English summary
      - recommended_actions: list[str] of suggested remediations
    """
    # Build a concise prompt – include only the relevant fields
    system = (
        "You are a SOC triage assistant. Output STRICT JSON with keys: "
        "severity (low|medium|high|critical), confidence (0-1), mitre, "
        "explanation, recommended_actions (list of 1-3 terse steps)."
    )
    user = (
        "Classify this alert. If it looks like a false positive, set severity low.\n"
        f"Alert JSON:\n{json.dumps(alert)[:6000]}"
    )

    response = requests.post(
        f"{OLLAMA_URL}/api/chat",
        json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": 0.2},
        },
        timeout=60,
    )
    response.raise_for_status()

    content = response.json()["message"]["content"].strip()
    # Some models wrap JSON in code fences – strip backticks and possible “json” prefix
    cleaned = content.strip("`").replace("json\n", "")
    return json.loads(cleaned)
