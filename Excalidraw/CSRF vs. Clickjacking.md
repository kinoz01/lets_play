
Setting the **`X-Frame-Options`** header is the standard way to prevent your content from being *embedded in a frame or iframe on another website*.

---

## 🖼️ How `X-Frame-Options` Works

The `X-Frame-Options` HTTP response header tells the browser whether it should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>`, or `<object>` tag.

It directly addresses the security issue that arises when one site embeds content from another.

### Common Directives

There are two primary directives you can set:

1. **`X-Frame-Options: DENY`**
    
    - **Effect:** The page cannot be displayed in a frame, regardless of the site attempting to do the framing. This is the **most restrictive** and safest setting.
        
2. **`X-Frame-Options: SAMEORIGIN`**
    
    - **Effect:** The page can only be displayed in a frame on a page that is part of the **same origin** (same protocol, domain, and port). For example, a page from `app.com` can be framed by another page from `app.com`, but _not_ by a page from `evil.com`.
        

### The Security Problem it Solves: Clickjacking

Clickjacking (or UI Redress) is an attack that relies entirely on embedding.

- **How it works:** An attacker frames your trusted site (`mybank.com`) on their malicious site (`evil.com`). They then set the iframe to be transparent and carefully position it over a button on `evil.com` that the user _intends_ to click.
    
- The user clicks what they think is a button on `evil.com`, but they are actually clicking the hidden, embedded button (e.g., "Confirm Transfer") on `mybank.com`.
    
- **The Defense:** By setting `X-Frame-Options: DENY`, your server tells the user's browser, "Do not allow any site to frame me." This breaks the core mechanism of the Clickjacking attack.
    

---

## 🔗 The Distinction: CSRF vs. Clickjacking

While `X-Frame-Options` is a great security measure, it's important to differentiate its purpose from the **CSRF (Cross-Site Request Forgery)** problem we discussed earlier:

|**Security Header/Mechanism**|**Problem Addressed**|**How the Attack Works**|
|---|---|---|
|**`X-Frame-Options`**|**Clickjacking**|Tricks the user into clicking a hidden UI element. Requires the page to be **visible** (even if transparent).|
|**CSRF Token**|**Cross-Site Request Forgery**|Tricks the browser into **submitting a request** (usually via a hidden form/script). Does **not** require the page to be visible.|

Because CSRF attacks often rely on simple, unseen form submissions (not embedding the entire UI), **`X-Frame-Options` does not fully protect against CSRF.** It only protects against the specialized attack that uses embedding (Clickjacking).