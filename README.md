<h1>🔐 SSLCheck</h1>
<h3>Advanced SSL/TLS Security Scanner & Certificate Analyzer</h3>

<p>
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status: active" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/license-CC%20BY--NC%204.0-lightgrey" alt="License: CC BY-NC 4.0" />
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows-lightgrey" alt="Platform Support" />
</p>

<hr />

<h2>🔍 Overview</h2>
<p>
<strong>SSLCheck</strong> is a Python-based SSL/TLS analysis tool that connects to a target domain and evaluates:
</p>

<ul>
  <li>Certificate validity & expiration</li>
  <li>Self-signed certificate detection</li>
  <li>TLS protocol version & deprecated protocols</li>
  <li>Weak cipher suites</li>
  <li>Forward secrecy (PFS)</li>
  <li>Domain mismatch issues</li>
  <li>Signature algorithm strength</li>
  <li>Certificate chain validity</li>
  <li>HSTS enforcement</li>
</ul>

<p>
Designed for cybersecurity analysts, penetration testers, DFIR responders, and administrators validating TLS security posture.
</p>

<hr />

<h2>✨ Features</h2>

<h3>🔒 Certificate Analysis</h3>
<ul>
  <li>Expiration & validity checks</li>
  <li>Self-signed detection</li>
  <li>Domain mismatch detection</li>
  <li>Weak signature algorithms (SHA1)</li>
  <li>Certificate chain parsing</li>
</ul>

<h3>⚙ TLS Security Analysis</h3>
<ul>
  <li>Protocol version detection</li>
  <li>Deprecated protocol alerts (SSLv2/3, TLS 1.0/1.1)</li>
  <li>Weak cipher detection (RC4, DES, 3DES, NULL, EXPORT, etc.)</li>
  <li>Forward secrecy validation (ECDHE/DHE)</li>
</ul>

<h3>🌐 HTTP Security Headers</h3>
<ul>
  <li>HSTS (Strict-Transport-Security) detection</li>
</ul>

<h3>📝 Output & Logging</h3>
<ul>
  <li>Clear CLI report output</li>
  <li>Structured logging to <code>ssl_checker.log</code></li>
</ul>

<hr />

<h2>📦 Installation</h2>

<h3>Requirements</h3>
<ul>
  <li>Python 3.10+</li>
  <li><code>cryptography</code> package</li>
  <li><code>requests</code> package</li>
</ul>

<h3>Install Dependencies</h3>
<pre><code class="language-bash">pip install requests cryptography
</code></pre>

<h3>Run the Tool</h3>
<pre><code class="language-bash">python3 sslcheck.py example.com
</code></pre>

<hr />

<h2>🖥 Example Output</h2>

<pre><code>
Performing SSL/TLS analysis for example.com...

Certificate: ✅ Valid
Self-Signed: ❌ Self-Signed Certificate
Protocol Status: ❌ Deprecated Protocol Detected: TLSv1
Cipher Suite: TLS_AES_256_GCM_SHA384
Forward Secrecy: ❌ No Forward Secrecy
Domain Status: ❌ Domain Mismatch
Signature Algorithm: ❌ Weak Signature Algorithm: sha1
Certificate Chain: ❌ Invalid Certificate Chain
HSTS: ❌ HSTS Not Enabled
</code></pre>

<hr />

<h2>📜 License</h2>
<p>
Licensed under the Creative Commons Attribution–NonCommercial 4.0 International License (CC BY-NC 4.0).<br />
See the LICENSE file for details.
</p>

<hr />
