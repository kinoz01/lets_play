That behavior—where you couldn't run JavaScript defined in a `<script>` tag because it wasn't served by your own server—is **not** a direct function of the **Same-Origin Policy (SOP)**.

Instead, you were almost certainly running into the security measure known as **Content Security Policy (CSP)**.

---

## 🚫 Content Security Policy (CSP)

CSP is an advanced security standard designed to **mitigate certain types of code injection attacks**, particularly **Cross-Site Scripting (XSS)**, by telling the browser exactly which sources of content (scripts, styles, images, etc.) are trusted and allowed to load or execute.

### 1. The Mechanism: Whitelisting

CSP is implemented via an HTTP response header (e.g., `Content-Security-Policy: ...`) sent by the server. This header contains directives that act as rules for the browser.

|**CSP Directive**|**Control**|
|---|---|
|**`script-src`**|Controls where JavaScript code can be loaded from.|
|**`style-src`**|Controls where CSS stylesheets can be loaded from.|
|**`default-src`**|Acts as a fallback for the other source directives.|

### 2. The Cause of Your Problem: Inline and Remote Scripts

The reason your JavaScript wouldn't run is because the server had likely implemented a strict CSP that explicitly banned two things:

#### A. **Banning Inline Scripts (`'unsafe-inline'` removed)**

If your JS code was directly embedded in the HTML:

```html
<script>
    // Your code here
</script>
```

A strict CSP often bans this to prevent an attacker from injecting code directly into the HTML (the primary goal of XSS). To enforce this, the server's CSP header would **not** include the `'unsafe-inline'` source keyword.

#### B. **Banning Untrusted Remote Scripts**

If your JS code was loaded from another domain (a third-party server):

```html
<script src="https://unauthorized.cdn.com/script.js"></script> 
```

The server's CSP likely used a whitelist that did **not** include `https://unauthorized.cdn.com`. The `script-src` directive would only list trusted sources (e.g., `script-src 'self' https://trusted.cdn.com`). If the source isn't on the list, the browser refuses to download and execute the script.

### 3. CSP vs. SOP (The Fucking Distinction)

You must keep these two security models separate in your head:

|**Feature**|**Same-Origin Policy (SOP)**|**Content Security Policy (CSP)**|
|---|---|---|
|**What it Checks**|**Where the data/response comes from.**|**Where the code/content is loaded from.**|
|**Goal**|Prevents scripts from **reading sensitive data** from a different origin.|Prevents scripts from **running malicious code** (XSS/injection) regardless of origin.|
|**Enforcer**|Default browser setting; no special header needed.|Server-sent HTTP header (`Content-Security-Policy`).|
|**Your Issue**|**Not related.** The script runs in the document's origin anyway.|**Directly related.** The script's source was not whitelisted.|