That's an excellent and very common question! The simple answer is that the browser **doesn't** send _all_ cookies to every request. It only sends the cookies that are scoped to the **domain** and **path** of the resource being requested.
Here is the breakdown of the rules and the security problem they create.

---

## 1. The Historical Default Rule (The "Why")

Cookies were designed to solve the problem of **HTTP being stateless**. Every time you load a page, the server has to be reminded who you are and what you're doing.

The original, basic rule for browsers was:

> 🔐 **Rule:** If a request is made to `example.com/api/data`, the browser must attach **every** cookie it has saved that is valid for the domain `example.com` (and the path `/api/data`).

The browser _has_ to send these cookies automatically because, from the server's perspective, **that is your entire identity**. If the server needs your session ID to know you're logged in, the browser must send it on every single request, or you'd be logged out on every click.

### Example of the Scope Rule

If you are on `www.siteA.com` and you request an image from `www.siteB.com/logo.png`, your browser will **only** send the cookies set by `www.siteB.com`. It **will not** send your cookies from `www.siteA.com`.

The problem arises when a page **embeds** content from another site.

---

## 2. The Vulnerability: Third-Party & Cross-Site Requests

The danger, which leads to your frustration, comes from the fact that the browser will automatically include cookies even if the request is **triggered** by a malicious site.

### The Problematic Case: Ambiguous Authority

Imagine you are on `evil.com`, but `evil.com` embed a hidden image or form that secretly targets your banking site, `bank.com` (embedding [[CSRF vs. Clickjacking]]) .

1. **The Attacker's Intent:** Send a request to `bank.com/transfer_money`.
    
2. **The Browser's Action:** When the browser attempts to send this request to `bank.com`, it checks its storage and sees the valid cookie (`session_id=123`) for `bank.com`.
    
3. **The Fatal Flaw:** The browser automatically attaches the cookie, even though the instruction to send the request came from `evil.com`.
    
4. **The Server's View:** The server at `bank.com` receives the request with a valid cookie and correctly assumes the logged-in user (you) intended to send the transfer request.
    

This is the **Cross-Site Request Forgery (CSRF)** vulnerability we discussed earlier. The cookie is what security professionals call an **"Ambient Authority"**—it's automatically included in the environment, which is powerful but dangerous.

---

## 3. The Modern Solution: The `SameSite` Attribute

To fix this exact problem and stop the browser from automatically betraying the user, developers now use the `SameSite` cookie attribute.

The `SameSite` attribute tells the browser **exactly when** it is safe to send a cookie. It has three main values:

|**SameSite Value**|**When the Browser Sends the Cookie**|**Security Implication**|
|---|---|---|
|**Strict**|ONLY when the request originates from the same site.|**Highest Security.** Prevents CSRF completely. (e.g., If you click a link on Google to go to your bank, the bank cookie won't be sent on that first navigation.)|
|**Lax**|Sent when navigating directly to the site (e.g., clicking a link).|**New Default.** Allows for basic external links but prevents most CSRF attacks via hidden forms/iframes.|
|**None**|Sent with all requests, even from third-party sites.|**Low Security.** This is only used for legitimate cross-site features like tracking or third-party widgets, and **requires** the `Secure` attribute (HTTPS).|

By adopting **`SameSite=Lax`** as the browser default, the web has significantly reduced the problem you described. The browser is now much smarter about sending cookies only when it's appropriate for the _user_ to be navigating there, rather than whenever a script on a random site requests it.

**Note:**
we have also, moderate CSRF protection, send cookie on links but not on embedded requests: `SameSite: http.SameSiteLaxMode`