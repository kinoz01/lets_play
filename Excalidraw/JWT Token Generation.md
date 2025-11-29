```java
public String generateToken(UserDetails userDetails) {
		return generateToken(new HashMap<>(), userDetails);
	}
	
	public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
		return Jwts.builder().setClaims(extraClaims).setSubject(userDetails.getUsername())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + expiration))
				.signWith(getSignInKey(), SignatureAlgorithm.HS256).compact();
	}
```

`generateToken` method is a public convenience method that immediately calls the more powerful, overloaded version: `generateToken(new HashMap<>(), userDetails)`.

1. **Preparation:** It creates an empty `HashMap<>()` for any optional extra claims.
    
2. **Delegation:** It passes the empty map and the user details to the core generation method.
    

### C. The Core Generation Process (Inside the Overloaded Method)

This is where the magic happens, handled by the JJWT library:

1. **The Payload (Claims):** The system builds the token's central data structure (the **payload** or **claims**):
    
    - **Subject (`sub`):** Set to `userDetails.getUsername()`. This identifies the user.
        
    - **Issued At (`iat`):** Set to the current time.
        
    - **Expiration (`exp`):** Set to `issuedAt` time plus the configured `expiration` duration (e.g., 1 hour).
        
    - **Header:** The token type (`JWT`) and the algorithm (`HS256`) are also prepared.
        
2. **The Signing (Hashing and Security):**
    
    - The Header and the Payload are encoded into Base64 (but not yet joined).
        
    - The system takes the encoded Header, the encoded Payload, and the **Secret Key** (from your configuration).
        
    - It feeds these three pieces into the **HS256 Hashing Algorithm**. This algorithm performs a one-way transformation (hashing). The resulting hash is the **Signature**.
        
3. The Assembly: The final JWT is assembled by concatenating the three parts with dots:
    
    $$Base64Url(Header) . Base64Url(Payload) . Signature$$
    
4. **The Result:** A compact, signed JWT string is returned to your login controller.