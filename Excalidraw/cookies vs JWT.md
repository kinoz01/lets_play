Why the JTW isn't attached and the cookie is attached??

That's the fundamental difference between modern, stateless authentication (JWTs in headers) and traditional, stateful authentication (Session Cookies).

The reason lies entirely in the **browser's default security rules**—specifically, how different storage mechanisms are handled during HTTP requests.

---

## 🍪 1. The Rule for Cookies: Ambient Authority

Cookies are automatically attached because they were designed to carry the Session ID, which is essential for maintaining state across multiple requests in the fundamentally stateless HTTP protocol.

- **Mechanism:** Cookies are stored in a special, dedicated space that is scoped to the domain and path (e.g., `mybank.com`).
    
- **Automatic Attachment:** When the browser makes _any_ request (whether from a URL typed in the address bar, an image tag, a simple HTML form, or a JavaScript request) to a domain, it automatically attaches all valid cookies for that domain.
    
- **Purpose:** This feature is necessary for **session management** (i.e., staying logged in).
    
- **Security Risk:** This automatic, **ambient authority** is what makes Session Cookies vulnerable to **CSRF (Cross-Site Request Forgery)**, as the browser blindly sends the credentials even when the request is triggered by an attacker's site.
    

## 🔑 2. The Rule for JWTs: Manual Control

JWTs (JSON Web Tokens) are typically stored in the browser's **`localStorage`** or **`sessionStorage`**. They are _not_ automatically attached to requests.

- **Mechanism:** `localStorage` and `sessionStorage` are private areas accessible **only** by JavaScript code that originated from the same domain (**Same-Origin Policy**).
    
- **Manual Attachment:** To send a JWT, the client-side JavaScript code must:
    
    1. **Retrieve** the token from `localStorage`.
        
    2. **Manually inject** the token into the HTTP request, usually in the `Authorization: Bearer <token>` header.
        
- **Purpose:** This shift to manual control makes the application **stateless** and protects against CSRF.
    
- **Security Benefit:** If an attacker's site (`evil.com`) tries to submit a request to your API (`myapi.com`), the attacker's script **cannot** access your token in your browser's `myapi.com` `localStorage` due to the Same-Origin Policy. Furthermore, the browser **never** automatically attaches `Authorization` headers to requests initiated from simple HTML forms or cross-site contexts.
    

---

## 📊 Summary of the Difference

|Feature|Session Cookies (Vulnerable to CSRF)|JWT in Authorization Header (CSRF-Safe)|
|---|---|---|
|**Storage Location**|Browser's dedicated Cookie Jar|`localStorage` or `sessionStorage`|
|**Transmission**|**Automatic** by the browser for every request to the domain.|**Manual** via JavaScript code on the client side.|
|**Cross-Site Behavior**|Sent automatically even if the request is triggered by an external site.|**Never** sent automatically. Requires script execution and manual header injection.|
|**CSRF Defense**|Requires an added layer (CSRF Token) to stop the abuse of the auto-sent cookie.|Inherently protected because the credentials (the token) are not automatically sent.|

Exporter vers Sheets