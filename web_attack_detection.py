import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
from typing import List

# --- Payload loader (plain text file, one payload per line) ---
def load_payloads_from_file(file_path: str) -> List[str]:
    p = Path(file_path)
    if not p.is_file():
        return []
    try:
        with p.open('r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []

# --- SQL detection (rule-based) ---
SQL_KEYWORDS = {
    "select", "from", "where", "insert", "update", "delete",
    "create", "alter", "drop", "or", "union", "group", "concat"
}
SQL_SPECIAL_CHARS = {"'", "-", "(", ")", ";", "#", '"', "--"}

def contains_sql_keyword(s: str) -> bool:
    lower = s.lower()
    return any(keyword in lower for keyword in SQL_KEYWORDS)

def contains_sql_special_char(s: str) -> bool:
    return any(char in s for char in SQL_SPECIAL_CHARS)

def contains_sql_payload(s: str, payloads: List[str]) -> bool:
    lower = s.lower()
    return any(payload.lower() in lower for payload in payloads)

def detect_sql_injection(s: str, payloads: List[str]) -> bool:
    return contains_sql_keyword(s) or contains_sql_special_char(s) or contains_sql_payload(s, payloads)

# --- XSS detection (rule-based) ---
XSS_KEYWORDS = {
    "script", "img", "iframe", "link", "object", "embed", "style", "base",
    "form", "input", "textarea", "javascript:", "alert", "prompt", "confirm",
    "eval", "settimeout", "setinterval", "window", "document", "cookie",
    "localstorage", "sessionstorage", "innerhtml", "outerhtml",
    "onload", "onerror", "onclick", "onmouseover", "onmouseout", "onchange",
    "onsubmit", "onfocus", "onblur", "onkeypress", "onkeydown", "onkeyup",
    "src", "href", "action", "data"
}
XSS_SPECIAL_CHARS = {'<', '>', '"', "'", '&', '(', ')', '[', ']', ';', '{', '}', '/'}

def contains_xss_keyword(s: str) -> bool:
    lower = s.lower()
    return any(keyword in lower for keyword in XSS_KEYWORDS)

def contains_xss_special_char(s: str) -> bool:
    return any(char in s for char in XSS_SPECIAL_CHARS)

def contains_xss_payload(s: str, payloads: List[str]) -> bool:
    lower = s.lower()
    return any(payload.lower() in lower for payload in payloads)

def detect_xss(s: str, payloads: List[str]) -> bool:
    return contains_xss_keyword(s) or contains_xss_special_char(s) or contains_xss_payload(s, payloads)

# --- GUI and interaction ---
DEFAULT_PAYLOAD_FILE = ""  # empty by default; user can choose via dialog

def choose_payload_file():
    global DEFAULT_PAYLOAD_FILE
    path = filedialog.askopenfilename(
        title="Select payload file (one payload per line)",
        filetypes=[("Text files", "*.txt *.csv"), ("All files", "*.*")]
    )
    if path:
        DEFAULT_PAYLOAD_FILE = path
        payload_label_var.set(f"Payload file: {Path(path).name}")

def on_button_click():
    user_input = entry.get().strip()
    if not user_input:
        messagebox.showwarning("Input required", "Please enter a URL or input to analyze.")
        return

    payloads = load_payloads_from_file(DEFAULT_PAYLOAD_FILE) if DEFAULT_PAYLOAD_FILE else []

    sql_detected = detect_sql_injection(user_input, payloads)
    xss_detected = detect_xss(user_input, payloads)

    results = []
    if sql_detected:
        results.append("SQL injection: DETECTED")
    else:
        results.append("SQL injection: Not detected")

    if xss_detected:
        results.append("XSS: DETECTED")
    else:
        results.append("XSS: Not detected")

    result_text.set("  |  ".join(results))

# Build UI
root = tk.Tk()
root.title("Simple Rule-based Web Attack Detector")
root.geometry("560x220")

tk.Label(root, text="Input to analyze:", font=('Helvetica', 11)).pack(pady=(12, 4))

entry = tk.Entry(root, width=80)
entry.pack(pady=6, padx=10)

controls_frame = tk.Frame(root)
controls_frame.pack(pady=(6, 8))

choose_btn = tk.Button(controls_frame, text="Choose payload file", command=choose_payload_file)
choose_btn.grid(row=0, column=0, padx=6)

run_btn = tk.Button(controls_frame, text="Check for vulnerabilities", command=on_button_click)
run_btn.grid(row=0, column=1, padx=6)

payload_label_var = tk.StringVar(value="Payload file: (not selected)")
tk.Label(root, textvariable=payload_label_var, font=('Helvetica', 9)).pack(pady=(0,6))

result_text = tk.StringVar(value="No analysis yet.")
tk.Label(root, textvariable=result_text, font=('Helvetica', 10)).pack(pady=6)

root.mainloop()
