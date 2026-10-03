import math
import os
import re
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI()

def load_common_passwords():
    paths = [
        "10k-most-common.txt",
        os.path.join(os.path.dirname(__file__), "10k-most-common.txt")
    ]
    for path in paths:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return {line.strip().lower() for line in f if line.strip()}
    return set()

COMMON_PASSWORDS = load_common_passwords()
COMMON_SUBSTRINGS = [w for w in COMMON_PASSWORDS if len(w) >= 5]

class PasswordRequest(BaseModel):
    password: str

@app.post("/api/analyze")
def analyze(payload: PasswordRequest):
    pwd = payload.password
    length = len(pwd)
    pwd_lower = pwd.lower()
    
    has_lower = bool(re.search(r"[a-z]", pwd))
    has_upper = bool(re.search(r"[A-Z]", pwd))
    has_digit = bool(re.search(r"[0-9]", pwd))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pwd))

    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digit: pool_size += 10
    if has_symbol: pool_size += 33

    entropy = round(length * math.log2(pool_size), 2) if pool_size > 0 else 0.0

    has_common_pattern = False
    if length > 0 and COMMON_PASSWORDS:
        if pwd_lower in COMMON_PASSWORDS:
            has_common_pattern = True
        else:
            has_common_pattern = any(w in pwd_lower for w in COMMON_SUBSTRINGS)

    if entropy < 28 or length < 8:
        strength = "Very Weak"
        score = 1
    elif entropy < 45 or length < 10:
        strength = "Weak"
        score = 2
    elif entropy < 65:
        strength = "Moderate"
        score = 3
    elif entropy < 85:
        strength = "Strong"
        score = 4
    else:
        strength = "Very Strong"
        score = 5

    if has_common_pattern and score > 1:
        score = min(score - 1, 2)
        strength = "Weak" if score == 2 else "Very Weak"

    return {
        "length": length,
        "entropy": entropy,
        "strength": strength,
        "score": score,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "has_common_pattern": has_common_pattern,
        "loaded_database_count": len(COMMON_PASSWORDS)
    }

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Password Strength Analyzer</title>
  <style>
    :root {
      --bg: #121214;
      --card: #18181b;
      --border: #27272a;
      --text: #f4f4f5;
      --muted: #a1a1aa;
      --bar-bg: #27272a;
      --accent: #ffffff;
      --status-crit: #ef4444;
      --status-warn: #f59e0b;
      --status-pass: #10b981;
    }
    body.light {
      --bg: #f4f4f5;
      --card: #ffffff;
      --border: #e4e4e7;
      --text: #09090b;
      --muted: #71717a;
      --bar-bg: #e4e4e7;
      --accent: #09090b;
      --status-crit: #dc2626;
      --status-warn: #d97706;
      --status-pass: #059669;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: monospace;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      padding: 1rem;
    }
    .container {
      width: 100%;
      max-width: 520px;
      background: var(--card);
      border: 1px solid var(--border);
      padding: 1.5rem;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.75rem;
      margin-bottom: 1.25rem;
    }
    .title {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .btn {
      background: transparent;
      color: var(--text);
      border: 1px solid var(--border);
      padding: 4px 8px;
      font-family: inherit;
      font-size: 0.75rem;
      cursor: pointer;
    }
    .input-wrapper {
      position: relative;
      margin-bottom: 1rem;
    }
    input[type="password"], input[type="text"] {
      width: 100%;
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.75rem;
      font-family: inherit;
      font-size: 0.9rem;
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
    }
    .toggle-visibility {
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      background: transparent;
      border: none;
      color: var(--muted);
      cursor: pointer;
      font-family: inherit;
      font-size: 0.75rem;
    }
    .meter-container {
      height: 4px;
      background: var(--bar-bg);
      margin-bottom: 1rem;
      overflow: hidden;
    }
    .meter-bar {
      height: 100%;
      width: 0%;
      transition: width 0.2s, background-color 0.2s;
    }
    .metrics {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem;
      border: 1px solid var(--border);
      padding: 0.75rem;
      font-size: 0.75rem;
      margin-bottom: 1rem;
    }
    .metric-item {
      display: flex;
      justify-content: space-between;
    }
    .metric-label {
      color: var(--muted);
    }
    .checklist {
      list-style: none;
      font-size: 0.75rem;
      border: 1px solid var(--border);
      padding: 0.75rem;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.5rem;
    }
    .check-item {
      color: var(--muted);
    }
    .check-item.valid {
      color: var(--status-pass);
    }
    .check-item.invalid {
      color: var(--status-crit);
    }
  </style>
</head>
<body class="dark">
  <div class="container">
    <div class="header">
      <span class="title">SEC://PWD-ANALYZER</span>
      <button class="btn" id="themeBtn" onclick="toggleTheme()">(Light)</button>
    </div>

    <div class="input-wrapper">
      <input type="password" id="pwdInput" placeholder="ENTER PASSWORD..." autocomplete="off">
      <button class="toggle-visibility" id="visBtn" onclick="toggleVisibility()">SHOW</button>
    </div>

    <div class="meter-container">
      <div class="meter-bar" id="meterBar"></div>
    </div>

    <div class="metrics">
      <div class="metric-item">
        <span class="metric-label">LENGTH:</span>
        <span id="metricLength">0</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">ENTROPY:</span>
        <span id="metricEntropy">0.00 bits</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">STATUS:</span>
        <span id="metricStrength">EMPTY</span>
      </div>
      <div class="metric-item">
        <span class="metric-label">DATABASE:</span>
        <span id="metricPattern">CLEAR</span>
      </div>
    </div>

    <ul class="checklist">
      <li class="check-item" id="cLength">[ ] 12+ CHARACTERS</li>
      <li class="check-item" id="cUpper">[ ] UPPERCASE [A-Z]</li>
      <li class="check-item" id="cLower">[ ] LOWERCASE [a-z]</li>
      <li class="check-item" id="cDigit">[ ] NUMBERS [0-9]</li>
      <li class="check-item" id="cSymbol">[ ] SPECIAL SYMBOLS</li>
      <li class="check-item" id="cPattern">[ ] 10K LIST CLEAR</li>
    </ul>
  </div>

  <script>
    function toggleTheme() {
      const body = document.body;
      const btn = document.getElementById("themeBtn");
      if (body.classList.contains("dark")) {
        body.classList.remove("dark");
        body.classList.add("light");
        btn.innerText = "(Dark)";
      } else {
        body.classList.remove("light");
        body.classList.add("dark");
        btn.innerText = "(Light)";
      }
    }

    function toggleVisibility() {
      const input = document.getElementById("pwdInput");
      const btn = document.getElementById("visBtn");
      if (input.type === "password") {
        input.type = "text";
        btn.innerText = "HIDE";
      } else {
        input.type = "password";
        btn.innerText = "SHOW";
      }
    }

    const input = document.getElementById("pwdInput");
    input.addEventListener("input", async () => {
      const val = input.value;
      if (!val) {
        resetUI();
        return;
      }

      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: val })
      });
      const data = await res.json();
      updateUI(data);
    });

    function resetUI() {
      document.getElementById("meterBar").style.width = "0%";
      document.getElementById("metricLength").innerText = "0";
      document.getElementById("metricEntropy").innerText = "0.00 bits";
      document.getElementById("metricStrength").innerText = "EMPTY";
      document.getElementById("metricPattern").innerText = "CLEAR";
      
      const checks = ["cLength", "cUpper", "cLower", "cDigit", "cSymbol", "cPattern"];
      checks.forEach(id => {
        const el = document.getElementById(id);
        el.className = "check-item";
        el.innerText = el.innerText.replace("[x]", "[ ]").replace("[!]", "[ ]");
      });
    }

    function updateUI(data) {
      document.getElementById("metricLength").innerText = data.length;
      document.getElementById("metricEntropy").innerText = data.entropy + " bits";
      document.getElementById("metricStrength").innerText = data.strength.toUpperCase();
      document.getElementById("metricPattern").innerText = data.has_common_pattern ? "MATCHED" : "CLEAR";

      const bar = document.getElementById("meterBar");
      const width = (data.score / 5) * 100;
      bar.style.width = width + "%";

      if (data.score <= 1) bar.style.backgroundColor = "var(--status-crit)";
      else if (data.score <= 3) bar.style.backgroundColor = "var(--status-warn)";
      else bar.style.backgroundColor = "var(--status-pass)";

      setCheck("cLength", data.length >= 12, "12+ CHARACTERS");
      setCheck("cUpper", data.has_upper, "UPPERCASE [A-Z]");
      setCheck("cLower", data.has_lower, "LOWERCASE [a-z]");
      setCheck("cDigit", data.has_digit, "NUMBERS [0-9]");
      setCheck("cSymbol", data.has_symbol, "SPECIAL SYMBOLS");
      setCheck("cPattern", !data.has_common_pattern, "10K LIST CLEAR");
    }

    function setCheck(id, valid, text) {
      const el = document.getElementById(id);
      el.className = "check-item " + (valid ? "valid" : "invalid");
      el.innerText = (valid ? "[x] " : "[!] ") + text;
    }
  </script>
</body>
</html>
"""

@app.get("/")
def index():
    return HTMLResponse(HTML_PAGE)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)