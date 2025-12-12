from flask import Flask, request, jsonify
import os
import secrets
import time
import traceback

app = Flask(__name__)

# ---- Core secrets ----
FLAG = os.environ.get("FLAG", "flag{exception_handling_meltdown_by_kohar}")
DEBUG_SECRET = os.environ.get("DEBUG_SECRET", "dbg_" + secrets.token_hex(8))

# How long debug mode stays active after an exception (seconds)
DEBUG_WINDOW_SECONDS = 45

# Global timestamp until which debug mode is enabled
debug_enabled_until = 0


# --------- BAD GLOBAL ERROR HANDLER (THE VULNERABILITY) ---------
@app.errorhandler(Exception)
def handle_exception(e):
    """
    Mishandled exceptional conditions:
    - Any unhandled exception activates a global debug window.
    - The app responds with a generic error to the user, BUT
      state is changed so /debug_status starts leaking secrets.
    """
    global debug_enabled_until
    debug_enabled_until = time.time() + DEBUG_WINDOW_SECONDS

    # Log the error server-side (not shown to user here)
    stack = traceback.format_exc()
    print("UNHANDLED EXCEPTION:\n", stack)

    # Generic user-facing error (so they have to discover /debug_status)
    return """
    <h1>Something went wrong</h1>
    <p>An unexpected error occurred while processing your request.</p>
    <p>Please try again later.</p>
    """, 500


# --------- BASIC UI ---------
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
    input { width:100%; padding:8px; margin:6px 0 12px; border-radius:4px; border:1px solid #ccc; }
    footer { text-align:center; color:#777; font-size:12px; margin:20px 0; }
    code { background:#eee; padding:2px 4px; border-radius:3px; }
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
    <a href="/debug_status">Debug Status</a>
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
    <h2>Welcome to CTF #2: Mishandled Exceptions</h2>
    <p>This application is supposed to handle errors safely.</p>
    <p>However, exceptional conditions may leave the system in an
       <strong>insecure state</strong>.</p>
    <p>Your goal: trigger the right kind of failure and
       <strong>recover the hidden flag</strong>.</p>
    <p>Useful places to start:</p>
    <ul>
      <li><code>/calc</code> – a simple calculator</li>
      <li><code>/docs</code> – API documentation</li>
      <li><code>/debug_status</code> – shows internal debug state</li>
    </ul>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


@app.route("/hint")
def hint():
    body = """
    <h2>Hint</h2>
    <p>Sometimes errors do more than show a message;
       they can <strong>change how the system behaves</strong> for a short time.</p>
    <p>If you suspect exceptional conditions are mishandled,
       try providing inputs that cause failures, then
       check whether any internal endpoints behave differently
       <em>right after</em> an error.</p>
    <p>Timing may matter.</p>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


@app.route("/docs")
def docs():
    body = """
    <h2>API Documentation</h2>
    <h3>GET /calc</h3>
    <p>Perform a basic arithmetic operation.</p>
    <p>Query parameters:</p>
    <ul>
      <li><code>a</code> – first number</li>
      <li><code>b</code> – second number</li>
      <li><code>op</code> – one of: <code>add</code>, <code>sub</code>, <code>mul</code>, <code>div</code></li>
    </ul>
    <p>Example:</p>
<pre>
/calc?a=10&b=5&op=div
</pre>
    <p>No authentication is required. Should be safe... probably.</p>
    """
    return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


# --------- CALC ENDPOINT (WHERE WE FORCE EXCEPTIONS) ---------
@app.route("/calc")
def calc():
    """
    Vulnerable calculator:
    - Converts query params to floats.
    - Division by zero will raise ZeroDivisionError.
    - Missing or invalid parameters raise ValueError.
    We do NOT handle these here; they bubble up to the global error handler.
    """
    a_str = request.args.get("a", None)
    b_str = request.args.get("b", None)
    op = request.args.get("op", "add")

    if a_str is None or b_str is None:
        # This will be caught by global error handler too
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
        # If b == 0.0, this will raise ZeroDivisionError
        result = a / b
    else:
        raise ValueError(f"Unsupported operation: {op!r}")

    return jsonify({"a": a, "b": b, "op": op, "result": result})


# --------- HIDDEN DEBUG ENDPOINT (THE REAL LEAK) ---------
@app.route("/debug_status")
def debug_status():
    """
    This endpoint should never expose secrets,
    but due to mishandled exceptional conditions,
    it does when debug mode is active.
    """
    now = time.time()
    if now < debug_enabled_until:
        # Debug window active – leak sensitive info
        body = f"""
        <h2>DEBUG MODE ACTIVE</h2>
        <p>Debug mode is currently <strong>ENABLED</strong> due to a recent exception.</p>
        <p><strong>Debug Secret:</strong> <code>{DEBUG_SECRET}</code></p>
        <p><strong>Flag:</strong> <code>{FLAG}</code></p>
        <p>This information should never be exposed in production.</p>
        <p>Debug window expires at: {time.ctime(debug_enabled_until)}</p>
        """
        return BASE_HTML_TOP + body + BASE_HTML_BOTTOM
    else:
        body = """
        <h2>Debug Mode</h2>
        <p>Debug mode is currently <strong>OFF</strong>.</p>
        <p>Everything looks normal. Or does it?</p>
        """
        return BASE_HTML_TOP + body + BASE_HTML_BOTTOM


# --------- DEV ENTRYPOINT ---------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
