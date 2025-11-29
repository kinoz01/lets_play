## ⚙️ Detailed Explanation of `RateLimitingFilter`

The `RateLimitingFilter` extends Spring's `OncePerRequestFilter`, guaranteeing its logic runs exactly once for every incoming HTTP request.

### 1. Initialization and Configuration

| **Element**            | **Value**                                 | **Purpose**                                                                                                                                          |
| ---------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@Component`**       | N/A                                       | Marks this class as a Spring Bean, allowing it to be registered into the filter chain.                                                               |
| **`CAPACITY`**         | `100`                                     | The maximum number of tokens (requests) a bucket can hold.                                                                                           |
| **`REFILL_WINDOW_MS`** | `60_000` (1 minute)                       | The time interval over which the bucket is designed to fully refill.                                                                                 |
| **`cache`**            | `ConcurrentHashMap<String, SimpleBucket>` | Stores a separate **Token Bucket** (`SimpleBucket`) for every unique user IP address (`String`). Using `ConcurrentHashMap` makes it [[thread-safe]]. |
| [[ObjectMapper]]       | `ObjectMapper`                            | Used to serialize the `ApiError` object into a JSON response body when a request is blocked.                                                         |

---

### 2. The Core Logic: `doFilterInternal`

This method is executed for every incoming request that passes the `shouldNotFilter` check.

1. **Identify Client:**
    
    ```java
    String ip = request.getRemoteAddr();
    ```
    
    It extracts the IP address, which serves as the unique key for the rate-limiting mechanism.
    
2. **Get/Create Bucket:**
    
    ```java
    SimpleBucket bucket = cache.computeIfAbsent(ip, this::createBucket);
    ```
    
	[[computeIfAbsent]] retrieves the token bucket associated with the IP address. If the IP is new, `createBucket` is called to initialize a new `SimpleBucket` with full capacity.
    
1. **Consume Token (The Decision):**
    
    ```java
    if (bucket.tryConsume(1)) {
        filterChain.doFilter(request, response);
    } else {
        // ... Send 429 response
    }
    ```
    
    It attempts to consume one token.
    
    - **Success:** If a token is consumed, the request is allowed to pass down the [[filter chain]] to the controller (`filterChain.doFilter`).
        
    - **Failure:** If no token is available, the request is blocked. It sets the HTTP status to **429 Too Many Requests** and writes a JSON-formatted `ApiError` to the response body using the `objectMapper`.
---> [[How doFilter is related to the SecurityFilterChain and FilterChain]]

### 3. The Token Bucket Algorithm: `SimpleBucket` Class

This is an inner class that implements the **Token Bucket Algorithm**, which models resource consumption over time.

| **Method**                   | **Role**           | **Mechanism**                                                                                                                                                                                                                                                                                              |
| ---------------------------- | ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`refill()`**               | **Refill Tokens**  | Calculates how many tokens should have been added since the `lastRefill` time. The tokens are added based on the elapsed time relative to the `refillWindowMs`. The token count is capped at `capacity`.                                                                                                   |
| **`tryConsume(int amount)`** | **Consume Tokens** | **1.** Calls `refill()` to update the current token count. **2.** Checks if `tokens >= amount` (typically 1). **3.** If sufficient tokens exist, it deducts them and returns `true`. **4.** It is `synchronized` to ensure thread safety, as multiple requests from the same IP can arrive simultaneously. |
| **State Variables**          | N/A                | `tokens` (current available requests), `lastRefill` (timestamp of the last refill operation).                                                                                                                                                                                                              |
- [[how could elapsed be less than 0]]
- The [[synchronized]] keyword in `tryConsume(int amount)`
### 4. Bypass Logic

```java
protected boolean shouldNotFilter(HttpServletRequest request) {
    return "OPTIONS".equalsIgnoreCase(request.getMethod());
}
```

This is a standard requirement for web filters. It prevents the filter from running for **[[CORS]] preflight ([[OPTIONS]])** requests, ensuring those essential network checks are never rate-limited.

---

## ⏱️ Where it Fits in the Spring Boot Lifecycle

The `RateLimitingFilter` is a **Servlet Filter** and is therefore integrated into the web server infrastructure.

| **Lifecycle Step**                             | **Action Related to RateLimitingFilter**                                                                                                                                                                                                                   |
| ---------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **5. Perform Component Scanning**              | Spring detects the `RateLimitingFilter` due to the `@Component` annotation and registers its **Bean Definition**.                                                                                                                                          |
| **8. Instantiate all singleton beans**         | The `RateLimitingFilter` instance is created and registered as a bean.                                                                                                                                                                                     |
| **9. Create the embedded web server (Tomcat)** | The auto-configuration for the web server starts. Tomcat is created, and the Spring infrastructure registers this filter into Tomcat's **Servlet Filter Chain**.                                                                                           |
| **10. Start the embedded server**              | Tomcat starts, and the filter is now active within the request processing pipeline.                                                                                                                                                                        |
| **14. Application listens for HTTP requests**  | **This is when the filter executes.** For every incoming HTTP request, the filter chain is processed, and the `doFilterInternal` method of the `RateLimitingFilter` runs **before** the request ever reaches the `DispatcherServlet` and your Controllers. |

The filter acts as a **gatekeeper** at the very beginning of the request handling process.

---

> Note that you will need to add:

```java
private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
```

so the `ObjectMapper` would work correctly, this because we are creating our own instance of it. A better way is to just put:

```java
@Autowired
    private ObjectMapper objectMapper;
``` 

so Spring will injected automatically for you with no need for optimal config manually.