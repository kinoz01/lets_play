The **Same-Origin Policy (SOP)** is a **fundamental, mandatory security model** enforced by all modern web browsers. It dictates the rules for how a document or script loaded from one origin can interact with resources loaded from another origin.

It is designed to isolate potentially malicious documents and is the single most important security mechanism in the browser's architecture, preventing websites from attacking each other.

---

## 🔐 The Core Rule: Definition of an "Origin"

An "origin" is defined by the unique combination of three distinct components of a URL:

1. **Protocol (Scheme):** The transfer protocol (e.g., `http://`, `https://`).
    
2. **Hostname (Domain):** The fully qualified domain name (e.g., `www.example.com`).
    
3. **Port:** The port number used for the connection (e.g., `:80`, `:443`, or an explicitly defined port like `:8080`).
    

|**Requesting Origin**|**Target Origin**|**Same Origin?**|**Reason**|
|---|---|---|---|
|`https://app.bank.com:443`|`https://app.bank.com:443`|**Yes**|All three components match.|
|`https://app.bank.com:443`|`http://app.bank.com:443`|**No**|**Protocol** mismatch (`https` vs `http`).|
|`https://app.bank.com`|`https://api.bank.com`|**No**|**Hostname** mismatch (`app` vs `api` subdomain).|
|`https://app.bank.com:443`|`https://app.bank.com:8080`|**No**|**Port** mismatch (`443` vs `8080`).|

## 🚫 What SOP Restricts (The Security Barrier)

The SOP strictly controls what **JavaScript** (client-side code) can do when communicating across origins. The key restriction is placed on **reading data** from a different origin.

If a script loaded from `https://trusted.com` makes a request to `https://evil.com`, the SOP mandates that:

1. **The Request is Usually Allowed:** The browser typically allows the **outgoing** HTTP request to be sent (this is necessary for things like [[CSRF]], which is a separate vulnerability).
    
2. **The Response is Hidden:** The browser **blocks the script from reading the response data** from `https://evil.com`.
    

### Why This is Critical:

Imagine you are logged into `https://mybank.com`. A malicious website, `https://phishing.com`, contains a script that uses `fetch()` to call an API endpoint at `https://mybank.com/transfer_history`.

- **Without SOP:** The script could read your entire transfer history (since the browser automatically sends your bank cookies), steal the data, and send it back to the attacker.
    
- **With SOP:** The browser allows the request to be sent to the bank, but when the bank's sensitive response arrives, the browser sees the origin mismatch and immediately **throws a security error**, preventing the `phishing.com` script from ever accessing the response data.
    

## ✅ How to Relax SOP: CORS

Because modern web applications often need to share resources (e.g., a JavaScript frontend on `app.com` needs to call a backend API on `api.com`), the SOP is often too restrictive.

The standard solution to intentionally bypass SOP is **Cross-Origin Resource Sharing (CORS)**.

- CORS is a set of **HTTP headers** that a server (the target of the request) can send to the browser.
    
- By setting the **`Access-Control-Allow-Origin`** header (e.g., `Access-Control-Allow-Origin: https://app.com`), the server explicitly tells the browser: **"It's safe; you can let the JavaScript on this specific origin read this response."**
    
- If the required CORS headers are missing or do not match the requesting origin, the SOP block remains active.

---
## Does SOP restrict JS from running

No, that is a common **misconception** regarding the **Same-Origin Policy (SOP)**.

The SOP does **not** restrict where the JavaScript (JS) code can run. JS code runs on the client machine regardless of its origin. The SOP restricts **what the JS code can do** once it's running.

Here is the goddamn distinction:

---

## 1. 🌐 The Source of Execution (Not Restricted)

JavaScript is designed to be embedded and executed by the browser's engine.

- **Serving is Allowed:** The SOP **does not prevent** a browser on one origin (e.g., `https://mybank.com`) from loading and running a JavaScript file served from a completely different origin (e.g., `https://cdn.malicious.com`).

    
    ```html
    <script src="https://cdn.malicious.com/tracking.js"></script> 
    ```
    
    This is allowed because scripts, images, and CSS are generally considered public resources that are **embedded** into the page. The browser grants permission for this initial resource loading.
    
- **Execution Location:** Once the bytes of `tracking.js` are downloaded, the code runs immediately within the **context and origin of the main document** (`https://mybank.com`). It has full, immediate access to the **DOM** (Document Object Model) and all local cookies/storage associated with `https://mybank.com`.

Here we must use [[CSP]]