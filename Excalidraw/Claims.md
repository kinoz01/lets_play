Claims are simply **pieces of information** asserted about a subject, typically a user, within a security token like a JWT (JSON Web Token).1

In the context of JWTs, the claims are the token's **payload**—the data held inside the token that is cryptographically signed.2

---

## 1. What are Claims? 📝

A JWT is composed of three parts: Header, Payload, and Signature.3 The **Payload** is the set of claims, which are stored as a JSON object.4

Each claim is a **key-value pair** that conveys a specific piece of information.5

### Examples of Claims:

|**Claim Key**|**Claim Type**|**Value**|**Meaning**|
|---|---|---|---|
|**`sub`**|Registered (Standard)|`"alice@example.com"`|**Subject:** Who the token is about (usually the User ID or email).|
|**`exp`**|Registered (Standard)|`1732953600`|**Expiration Time:** The time after which the token must not be accepted.|
|**`iss`**|Registered (Standard)|`"api.mycompany.com"`|**Issuer:** Who created and signed the token.|
|**`role`**|Custom (Private)|`["ADMIN", "USER"]`|The user's application roles.|
|**`user_id`**|Custom (Private)|`42`|The user's internal database ID.|

Claims are categorized into three types:

1. **Registered Claims:** Pre-defined, standardized keys (like `iss`, `sub`, `exp`, `iat`) recommended by the JWT specification (RFC 7519).6 They are essential for interoperability.
    
2. **Public Claims:** Claims defined by people using JWTs, but designed to be used in public spaces. They must be registered in the IANA JSON Web Token Claims Registry to avoid collision.7
    
3. **Private Claims:** Custom claims used internally by your application (like `role` or `user_id`). These are not standardized but must be used carefully to avoid clashing with public or registered names.
    

---

## 2. Why are they called Claims? 🗣️

The term "claim" is used because the token is essentially an **assertion** or a **statement** about the entity it represents.

The usage is rooted in logic and cryptography:

- **Assertion:** When your server (the **Issuer**) creates a JWT and signs it, it is making verifiable claims about the **Subject**. For instance, the server is "claiming" that the user is Alice (`"sub": "alice@example.com"`) and "claiming" that this information is valid until a specific time (`"exp": 1732953600`).
    
- **Verification:** Because the entire token is digitally signed, any party that receives the token can verify that the claims haven't been changed since the server issued them.8
    

In short, "claims" is a formal term for the pieces of data that the token is asserting to be true and which the token receiver should rely on.