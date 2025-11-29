
A JSON Web Token (JWT) is essentially a compact, URL-safe data structure used to securely transmit information between two parties.1

It consists of **three parts**, which are concatenated together using **dots (`.`)** to form the final token string:

$$\text{JWT} = \text{Header} . \text{Payload} . \text{Signature}$$

---

## 1. The Header (JOSÉ) ⚙️

The Header, formally known as the **JSON Object Signing and Encryption (JOSÉ) Header**, is a JSON object that contains metadata about the token itself.

|**Claim Key**|**Example Value**|**Description**|
|---|---|---|
|**`typ`**|`"JWT"`|**Type:** Indicates the object is a JSON Web Token.|
|**`alg`**|`"HS256"`|**Algorithm:** Specifies the cryptographic algorithm used to sign the token (e.g., HMAC using SHA-256).|

- **Process:** This JSON structure is **Base64Url encoded** to form the first part of the JWT.2
    

---

## 2. The Payload (Claims) 📝

The Payload, known as the **Claims Set**, is a JSON object that contains the actual data (claims or assertions) about the subject (usually the user) and other token properties.

|**Claim Key**|**Example Value**|**Description**|
|---|---|---|
|**`sub`**|`"user@example.com"`|**Subject:** The principal the token is about (usually the user ID or email).|
|**`exp`**|`1764355200`|**Expiration Time:** A timestamp indicating when the token must no longer be accepted.|
|**`iat`**|`1764268800`|**Issued At:** The timestamp when the token was created.|
|**`role`**|`"ADMIN"`|A custom claim used by the application to hold user roles.|

- **Process:** This JSON structure is also **Base64Url encoded** to form the second part of the JWT.
    

---

## 3. The Signature (The Seal) 🔒

The Signature is the security guarantee of the JWT. It ensures the token hasn't been tampered with and verifies that the token was genuinely issued by the server.

- **Process:** The signature is created by taking the **encoded Header**, the **encoded Payload**, and a **Secret Key** (known only to the server) and feeding all three into the cryptographic algorithm specified in the Header (e.g., HS256).
    

$$\text{Signature} = \text{HS256}(\text{encodedHeader} + "." + \text{encodedPayload}, \text{SecretKey})$$

- **Verification:** When the server receives the token, it recalculates the signature using the same three inputs. If the locally calculated signature matches the signature attached to the token, the token is considered **valid and authentic**.


![[53ef2102-api-penetration-testing.png]]