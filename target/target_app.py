#!/usr/bin/env python3
"""
target_app.py - Vulnerable Flask Diagnostic API
================================================================================
Vulnerability : Server-Side Template Injection (SSTI) via Jinja2
MITRE ATT&CK  : T1190 (Exploit Public-Facing Application)
Kill Chain     : Phase 3 — Delivery / Initial Access

PRINCIPLE — Why SSTI Works
--------------------------
Flask uses Jinja2 as its template engine.  Jinja2 evaluates expressions inside
{{ }} delimiters in a sandboxed-but-escapable Python context.

The vulnerability arises from a two-step composition mistake:

  Step 1 — Python f-string interpolation
    template = f"Query: {user_input}"
    At this point user_input is literally pasted into the string.
    If user_input = "{{ 7*7 }}", the result is the string:
        "Query: {{ 7*7 }}"

  Step 2 — Jinja2 rendering
    render_template_string(template)
    Jinja2 now sees {{ 7*7 }} as a live expression and evaluates it → "49"

The SAFE pattern passes user data as a Jinja2 *variable*, not part of the
template source:
    render_template_string("Query: {{ q }}", q=user_input)
Here Jinja2 treats q as data, never as code.

SSTI → RCE Escalation Path
---------------------------
Jinja2 expressions can traverse Python's object model:
    config                               → Flask config object
    .__class__                           → <class 'flask.config.Config'>
    .__init__                            → bound method (Config.__init__)
    .__globals__                         → dict of module-level globals
    ['os']                               → the 'os' module (imported by flask.config)
    .popen('cmd')                        → subprocess execution → RCE

This works because:
  1. Python's introspection allows ANY object to reach its class, then the
     module globals of any method defined in that module.
  2. Flask's config module imports 'os' at module level, so 'os' lives in
     Config.__init__.__globals__.
  3. Jinja2's sandbox restricts *attribute names starting with _* by default,
     but config.__class__ is not underscore-prefixed — the sandbox checks
     are on the attribute NAME, not on the resolution chain.

Impact: Full Remote Code Execution with the privileges of the Flask process.

Usage: sudo python3 target_app.py [--port PORT]
================================================================================
"""
from flask import Flask, request, render_template_string
import argparse
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lab-secret-key-do-not-use-in-prod'

# Suppress Flask request logs for cleaner demo output
log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)


@app.route('/')
def index():
    # This page is safe — no user input in the template source.
    return render_template_string('''<!DOCTYPE html>
<html>
<head><title>Enterprise Diagnostic Portal</title></head>
<body>
<h2>System Diagnostic Portal v2.1</h2>
<p>Internal use only. Authorized personnel only.</p>
<form action="/diag" method="POST">
    <label>Diagnostic Query:</label><br>
    <input type="text" name="query" size="80"
           placeholder="Enter system check command..."><br><br>
    <input type="submit" value="Run Diagnostic">
</form>
<hr>
<small>DiagAPI v2.1.0 | Flask/Jinja2</small>
</body>
</html>''')


@app.route('/diag', methods=['GET', 'POST'])
def diag():
    query = request.form.get('query', request.args.get('query', ''))
    if not query:
        return 'Missing query parameter', 400

    # =================================================================
    # VULNERABILITY:  f-string interpolation + render_template_string
    # =================================================================
    #
    # WHY THIS IS DANGEROUS:
    #
    #   1. The f-string  f"...{query}..."  textually embeds the raw user
    #      input into the template *source code*.
    #
    #   2. render_template_string() then compiles that source into a
    #      Jinja2 AST and evaluates it.  Any {{ expr }} that came from
    #      the user is now executed as Jinja2 code.
    #
    # WHAT THE ATTACKER SENDS (via POST body):
    #
    #   query={{ config.__class__.__init__.__globals__['os']
    #            .popen('id').read() }}
    #
    # WHAT THE SERVER SEES after f-string expansion:
    #
    #   <pre>Query: {{ config.__class__.__init__.__globals__['os']
    #                   .popen('id').read() }}</pre>
    #
    # WHAT Jinja2 EVALUATES:
    #
    #   config → Config object
    #     .__class__.__init__.__globals__['os'] → os module
    #       .popen('id') → <_io.TextIOWrapper> (runs 'id' on the OS)
    #         .read() → "uid=0(root) gid=0(root) ..."
    #
    # SAFE ALTERNATIVE (data binding, not source interpolation):
    #
    #   return render_template_string(
    #       "<pre>Query: {{ q | e }}</pre>",   # q is a variable
    #       q=query                             # passed as context
    #   )
    #
    # With data binding, {{ q | e }} treats q as a *string value* and
    # applies Jinja2 auto-escaping.  Even if q contains "{{ 7*7 }}",
    # it renders as the literal text "{{ 7*7 }}", never evaluated.
    # =================================================================
    template = f'''<h3>Diagnostic Result</h3>
<pre>Query: {query}</pre>
<pre>Status: OK</pre>'''
    return render_template_string(template)


@app.route('/health')
def health():
    return 'OK', 200


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Vulnerable Diagnostic API')
    parser.add_argument('--port', type=int, default=9999)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()

    print(f"\033[93m{'='*55}")
    print(f"  Diagnostic API | {args.host}:{args.port}")
    print(f"  SSTI Vuln on /diag  (render_template_string + f-string)")
    print(f"{'='*55}\033[0m")
    app.run(host=args.host, port=args.port, debug=False)
