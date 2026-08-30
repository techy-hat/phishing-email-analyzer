import urllib.request, json, sys

# Force UTF-8 output so emoji in recommendations don't crash on Windows cp1252
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

phishing_email = (
    "From: PayPal Support <security@paypa1-secure-login.com>\n"
    "To: victim@example.com\n"
    "Subject: URGENT: Your PayPal account has been suspended - Verify immediately\n\n"
    "Dear Valued Customer,\n\n"
    "We have detected unauthorized access to your PayPal account. Your account will be\n"
    "permanently terminated within 24 hours unless you verify your credentials immediately.\n\n"
    "CLICK HERE TO VERIFY YOUR ACCOUNT:\n"
    "http://paypa1-secure-login.com/account/verify/login?user=victim@example.com\n\n"
    "You must act now. Failure to verify within 24 hours will result in permanent account\n"
    "suspension and possible legal action.\n\n"
    "Confirm your password and billing information at:\n"
    "http://192.168.1.105/paypal/webscr?cmd=_login-submit\n\n"
    "Your account has been flagged for suspicious activity. Do not ignore this final notice.\n\n"
    "PayPal Security Team\n"
)

data = json.dumps({"email": phishing_email}).encode()
req = urllib.request.Request(
    "http://localhost:8000/api/analyze",
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as resp:
    result = json.loads(resp.read())

print("=== PHISHGUARD ANALYSIS RESULT ===")
print("Score :", result["score"])
print("Level :", result["level"])
bd = result["breakdown"]
print("Breakdown: sender=%d  links=%d  content=%d" % (bd["sender"], bd["links"], bd["content"]))
print()
print("--- THREATS ---")
for t in result["threats"]:
    print("  [%s] %s: %s" % (t["severity"], t["title"], t["description"][:90]))
print()
print("--- FINDINGS ---")
for f in result["findings"]:
    print("  [%s] %s: %s" % (f["severity"], f["label"], f["text"][:90]))
print()
print("--- RECOMMENDATION ---")
print(result["recommendation"][:300])
print()
print("Response keys:", list(result.keys()))
