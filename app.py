from flask import Flask, request, jsonify
import os
import secrets
import time
import traceback

app = Flask(__name__)

# ---- Secrets ----
FLAG = os.environ.get("FLAG", "flag{exception_handling_meltdown_by_kohar}")
DEBUG_SECRET = os.environ.get("DEBUG_SECRET", "dbg_" + secrets.token_hex(8))

DEBUG_WINDOW_SECONDS = 45
debug_enabled_until = 0  # global "debug window" timer


# --------- BAD GLOBAL ERROR HANDLER (CORE VULN) ---------
@app.errorhandler(Exception)
def handle_exception(e):
    """
    Mishandled exceptional conditions:
    Any unhandled exception globally enables a debug window.
    The user sees a generic error, but the app enters an insecure debug state.
    """
    global debug_enabled_until
    debug_enabled_until = time.time() + DEBUG_WINDOW_SECONDS

    # Server-side logging (not shown to user)
    print("UNHANDLED EXCEPTION:\n", traceback.format_exc())

    # Generic error to the user
    return """
    <h1>Something went wrong</h1>
    <p>An unexpected error occurred while processing your request.</p>
    <p>Please try again later.</p>
    """, 500


# --------- UI WRAPPER ---------
BASE_HTML_TOP = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Kohar's Exception Handling CTF</title>
  <style>
    body { font-family: Arial, sans-serif; background:#f4f4f7; margin:0; padding:0; }
    header { background:#222; color:#fff; padding:10px 20px; }
    header h1 { margin:0; font-size:20px; }
    nav a { color:#fff; margin-right:15px; text-decoration:none; }
    nav a:hover { text-decoration:underline; }
    .container { max-width:900px; margin:20px auto; background:#fff;
                 padding:20px 25px; border-radius:8px; box-shadow:0 0 6px rgba(0,0,0,0.1); }
    .btn { background:#007bff; color:#fff; border:none; padding:8px 14px; border-radius:4px; cursor:pointer; }
    .btn:hover { background:#0056b3; }
    input, select { width:100%; padding:8px; margin:6px 0 12px; border-radius:4px; border:1px solid #ccc; }
    footer { text-align:center; color:#777; font-size:12px; margin:20px 0; }
    code { background:#eee; padding:2px 4px; border-radius:3px; }
    .note { color:#555; font-size:14px; }
  </style>
</head>
<body>
<header>
  <h1>Kohar's Exception Handling CTF</h1>
  <nav>
    <a href="/">Home</a>
    <a href="/calc">Calculator</a>
    <a href="/docs">API Docs</a>
    <a href="/hint">Hint</a>
  </nav>
</header>
<div class="container">
"""

BASE_HTML_BOTTOM = """
</div>
<footer>Kohar's Mishandled Exceptions CTF</footer>
</body>
</html>
"""


@app.route("/")
def index():
    body = """
    <h2>CTF #2: Mishandled Exceptional Conditions</h2>
    <p>This app is supposed to handle errors safely. It doesn't.</p>
    <p>Your goal: find a way to trigger a failure that changes the system into an insecure state,
       then use that state to retrieve the flag.</p>
    <p class="note">Tip: check <code>/docs</code> for intended behavior.</p>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


@app.route("/hint")
def hint():
    body = """
    <h2>Hint</h2>
    <p>Sometimes an error doesn't just return a 500… it can flip the application into a different mode.</p>
    <p>After you cause an exception, look for endpoints that behave differently for a short window.</p>
    <p>Also: don't assume the flag will be printed directly on a debug page.</p>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM

@app.route("/favicon.ico")
def favicon():
    # Return a 204 No Content so browsers stop complaining
    return ("", 204)


@app.route("/docs")
def docs():
    body = """
    <h2>API Documentation</h2>

    <h3>GET /api/calc?a=&amp;b=&amp;op=</h3>
    <p>Compute a result. Valid ops: <code>add</code>, <code>sub</code>, <code>mul</code>, <code>div</code></p>

    <h3>GET /debug_status</h3>
    <p>Displays whether the system is in debug mode.</p>

    <h3>GET /api/flag</h3>
    <p>Returns the flag only if a debug window is active and a valid debug token is supplied:</p>
    <pre>
X-DEBUG-TOKEN: &lt;token&gt;
    </pre>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


# --------- Calculator UI (does NOT crash when opened) ---------
@app.route("/calc", methods=["GET"])
def calc_ui():
    body = """
    <h2>Calculator</h2>
    <p class="note">This calculator should be stable… unless something unexpected happens.</p>

    <form method="GET" action="/api/calc">
      <label>A</label>
      <input name="a" placeholder="e.g. 10">

      <label>B</label>
      <input name="b" placeholder="e.g. 5">

      <label>Operation</label>
      <select name="op">
        <option value="add">add</option>
        <option value="sub">sub</option>
        <option value="mul">mul</option>
        <option value="div">div</option>
      </select>

      <button class="btn" type="submit">Compute</button>
    </form>

    <p class="note">API endpoint: <code>/api/calc?a=10&b=5&op=div</code></p>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


# --------- API Calculator (where exceptions can be triggered) ---------
@app.route("/api/calc")
def api_calc():
    """
    This is intentionally fragile:
    - float conversion can raise ValueError
    - division by zero can raise ZeroDivisionError
    - invalid op raises ValueError
    We do NOT catch these -> global handler triggers debug window.
    """
    a_str = request.args.get("a", None)
    b_str = request.args.get("b", None)
    op = request.args.get("op", "add")

    if a_str is None or b_str is None:
        raise ValueError("Both 'a' and 'b' parameters are required")

    a = float(a_str)
    b = float(b_str)

    if op == "add":
        result = a + b
    elif op == "sub":
        result = a - b
    elif op == "mul":
        result = a * b
    elif op == "div":
        result = a / b  # ZeroDivisionError if b == 0.0
    else:
        raise ValueError(f"Unsupported operation: {op!r}")

    return jsonify({"a": a, "b": b, "op": op, "result": result})


# --------- Debug status (no flag here anymore) ---------
@app.route("/debug_status")
def debug_status():
    now = time.time()
    if now < debug_enabled_until:
        body = f"""
        <h2>DEBUG MODE ACTIVE</h2>
        <p>Debug mode is currently <strong>ENABLED</strong> due to a recent exception.</p>
        <p><strong>Debug Token:</strong> <code>{DEBUG_SECRET}</code></p>
        <p class="note">This token should never be exposed in production.</p>
        <p>Debug window expires at: <code>{time.ctime(debug_enabled_until)}</code></p>
        <p class="note">Next step: use the token against <code>/api/flag</code> with header <code>X-DEBUG-TOKEN</code>.</p>
        """
        return BASE_HTML_TOP + body + BASE_HTML_BOTTOM
    else:
        body = """
        <h2>Debug Mode</h2>
        <p>Debug mode is currently <strong>OFF</strong>.</p>
        """
        return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


# --------- Flag endpoint (requires debug window + debug token) ---------
@app.route("/api/flag")
def api_flag():
    now = time.time()
    if now >= debug_enabled_until:
        return jsonify({"error": "Debug mode is OFF"}), 403

    token = request.headers.get("X-DEBUG-TOKEN", "")
    if token != DEBUG_SECRET:
        return jsonify({"error": "Invalid debug token"}), 403

    return jsonify({"flag": FLAG, "note": "Exceptional conditions must be handled safely."})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
