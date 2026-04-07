#!/usr/bin/env python3
"""
target_app.py - Vulnerable Flask Diagnostic API
MITRE ATT&CK: T1190

Intentionally vulnerable Flask app with an SSTI (Server-Side Template Injection)
flaw in the /diag endpoint. User input is interpolated into the template string
via f-string before render_template_string(), allowing Jinja2 expression injection
that escalates to RCE through config.__class__.__init__.__globals__['os'].popen().

Usage: sudo python3 target_app.py [--port PORT]
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
