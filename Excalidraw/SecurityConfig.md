--> [[SecurityConfig call]]

This Java class, **`SecurityConfig`**, is the blueprint for how your Spring Boot application handles all security, authentication, authorization, and network policies. It leverages **Spring Security** to lock down or permit access to your API endpoints.

I will break down this configuration, which establishes a modern **stateless REST API security model** using JSON Web Tokens (**JWTs**), CORS, and Rate Limiting.

---

## 1\. Class-Level Annotations

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig {
```

### [[@Configuration]]

-   Tells Spring: *“This class defines beans for the application context.”*
-   Any method annotated with `@Bean` inside this class will be executed at startup, and its return value will be registered as a Spring bean.
    
---

### [[@EnableWebSecurity]]

-   Turns on **Spring Security’s web support**.
-   It:
    
    -   Registers the Spring Security filter chain (`FilterChainProxy`) into the servlet filter chain.
        
    -   Activates the use of your `SecurityFilterChain` bean to configure HTTP security.
        

---

### `@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)`

This enables **[[method-level security]]**.

-   `prePostEnabled = true`  
    Allows use of:
    
    ```java
    @PreAuthorize("hasRole('ADMIN')")
    @PostAuthorize("returnObject.owner == authentication.name")
    ```
    
-   `securedEnabled = true`  
    Allows:
    
    ```java
    @Secured("ROLE_ADMIN")
    ```
    

So now you can secure **methods** (services, controllers, etc.) not only via URL paths.

---

## 2\. Constructor Injection

```java
private final JwtAuthenticationFilter jwtAuthenticationFilter;
private final RateLimitingFilter rateLimitingFilter;

@Autowired
public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, RateLimitingFilter rateLimitingFilter) {
    this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    this.rateLimitingFilter = rateLimitingFilter;
}
```

-   Spring creates instances of `JwtAuthenticationFilter` and `RateLimitingFilter` (both are `@Component`s).
    
-   It injects them into this config class via **constructor injection** (recommended best practice).
    
-   Marking fields `final` emphasizes they are required dependencies.
    

These filters will be plugged into the security filter chain later.
Those constructor parameters are the object instances (beans) that Spring injects when it creates `SecurityConfig`. Each corresponds to a bean in the application context. Spring resolves each parameter by type and passes the actual object into the constructor; by the time the constructor runs, you’re working with fully initialized bean instances, not the class definitions themselves.

---

## 3\. The Security Filter Chain

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.disable())
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(rateLimitingFilter, JwtAuthenticationFilter.class);

    return http.build();
}
```

This method defines **how HTTP security behaves**.

Spring Security will use this `SecurityFilterChain` to build the internal filter chain.

Let’s break each piece.

---

[[CORS, SOP, CSP, CSRF]]
### 3.1 `csrf(csrf -> csrf.disable())`

CSRF = Cross-Site Request Forgery protection.

-   CSRF is **important for web apps with sessions and cookies** (like form login).
    
-   For **[[stateless]] REST APIs** using JWT in the `Authorization` header:
    
    -   You typically **disable [[CSRF]]**, because:
        
        -   No session/auth cookie is used.
            
        -   The client (SPA / mobile / frontend) attaches a token explicitly.
            
-   That’s exactly what you’re doing here.
    

---

### 3.2 `cors(cors -> cors.configurationSource(corsConfigurationSource()))`

This enables [[CORS]] support and tells Spring Security to use your custom [[corsConfigurationSource() bean]].

This is needed when:

-   Cors setup relax [[Same-Origin Policy (SOP)]]
    
-   When set to allow-all (\*), the browser will stop sending and receiving cookies and tokens.

---

### 3.3 `sessionManagement(... STATELESS ...)`

```java
.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```

This is **super important for JWT-based APIs**:

-   `STATELESS` means:
    
    -   Spring **will not create** an HTTP session.
        
    -   Spring **will not use** the session to store `SecurityContext`.
        
-   Instead, **every request must carry credentials** (JWT token), and your filters handle auth **per request**.
    
-   This aligns perfectly with:
    
    -   `JwtAuthenticationFilter` (reads JWT each time)
        
    -   No server-side user session
        

---

### 3.4 Adding Custom Filters

```java
.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
.addFilterBefore(rateLimitingFilter, JwtAuthenticationFilter.class);
```

This defines the **order** of your custom filters in the Spring Security filter chain.

#### a) `jwtAuthenticationFilter` before `UsernamePasswordAuthenticationFilter`

```java
.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
```

This means:

> “Insert `JwtAuthenticationFilter` into the filter chain **just before** where Spring would put `UsernamePasswordAuthenticationFilter`.”

-   You are **not enabling** `UsernamePasswordAuthenticationFilter` (form login); you are just using it as a **position marker**, it's probably not even added to the filter chain.
    
-   Effectively, your `JwtAuthenticationFilter` runs **early**, before the normal authentication mechanisms.

Now downstream filters & the controller see the user as **authenticated**.

---

#### b) `rateLimitingFilter` before `JwtAuthenticationFilter`

```java
.addFilterBefore(rateLimitingFilter, JwtAuthenticationFilter.class);
```

This yields the following logical order:

```text
... → RateLimitingFilter → JwtAuthenticationFilter → UsernamePasswordAuthenticationFilter → ...
```

Meaning:

1.  **RateLimitingFilter** runs first:
    
    -   Checks request rate based on IP.
        
    -   If too many requests → returns `429 Too Many Requests` with JSON body.
        
    -   If allowed → calls `filterChain.doFilter(...)` → passes to next filter.
        
2.  **JwtAuthenticationFilter** runs second:
    
    -   Handles JWT auth as described.
        
3.  Then the rest of Spring Security filters...
4. calling [[http.build()]]
    
5.  Finally, if allowed, the request reaches the `DispatcherServlet` → your `@RestController`.
    

So the flow is:

```text
Client
  ↓
Tomcat
  ↓
Spring Security Filter Chain
  ↓
RateLimitingFilter
  ↓
JwtAuthenticationFilter
  ↓
[other filters...]
  ↓
DispatcherServlet
  ↓
Controller method (your endpoint)
```

If **any** filter decides not to call `filterChain.doFilter(request, response)`, the chain stops there.

---

## 4\. [[AuthenticationManager]] Bean

```java
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
}
```

-   `AuthenticationManager` is the core interface used by Spring Security to perform authentication.
    
-   `AuthenticationConfiguration` is a Spring-provided helper that:
    
    -   Builds an `AuthenticationManager` based on your `UserDetailsService`, `PasswordEncoder`, etc.
        
-   You expose the `AuthenticationManager` as a bean so you can inject it elsewhere (e.g. in a login service or an auth controller).

---> [[Why Spring Doesn't Inject AuthenticationManager Automatically]]

---

## 5\. PasswordEncoder Bean

```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

-   Defines the `PasswordEncoder` used to:
    
    -   Hash passwords when saving users.
        
    -   Verify raw passwords against hashed ones on login.
        
-   `BCryptPasswordEncoder` is the **recommended** encoder:
    
    -   Strong hashing algorithm.
        
    -   Built-in salt.
        
    -   Slow enough to resist brute-force attacks.
        

Anywhere you inject `PasswordEncoder`, you'll get this implementation.

---

## 6\. CORS Configuration

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of("*"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(false);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

This defines **how browsers are allowed to call your API from other origins**.

### `new CorsConfiguration()`

You configure:

#### `setAllowedOrigins(List.of("*"))`

-   Any origin (`*`) can call your API.
    
-   This is permissive — okay for dev and stateless setups.

#### `setAllowedMethods(...)`

```java
List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
```

-   These HTTP methods are allowed in cross-origin requests.
    

#### `setAllowedHeaders(List.of("*"))`

-   Any header is allowed in the request (e.g. `Authorization`, `Content-Type`, custom headers).
    

#### `setExposedHeaders(List.of("Authorization"))`

-   Tells the browser that the `Authorization` response header **should be exposed** to JavaScript.
    
-   Without this, JS running in the frontend cannot read that header even if the server sends it.
    

#### `setAllowCredentials(false)`

-   No cookies, auth headers **attached by the browser as credentials**, etc. are allowed automatically.
    
-   Combined with `*` origin, this is enforced also within the browser setup.  
    If `setAllowCredentials(true)`, then `*` is **not allowed**; you must specify exact origins.
    

---

### `UrlBasedCorsConfigurationSource`

```java
UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
source.registerCorsConfiguration("/**", configuration);
```

-   Applies this CORS configuration to **all endpoints** (`/**`).
    
-   Then the returned bean is used by:
    
    ```java
    .cors(cors -> cors.configurationSource(corsConfigurationSource()))
    ```
    
    in your `securityFilterChain`.
    

This means every request goes through CORS checks *before* being processed further.

---

## Putting It All Together: Full Request Lifecycle

When a client hits e.g. `GET /api/games`:

1.  **Tomcat** receives the HTTP request.
    
2.  Request is passed to the **Spring Security filter chain**.
    
3.  Filters run in order:
    
    -   `RateLimitingFilter`
        
        -   May reject with `429` or pass.
            
    -   `JwtAuthenticationFilter`
        
        -   May reject with `401` or set `SecurityContext` and pass.
            
    -   Other Spring Security filters (exception translation, authorization, etc.).
        
4.  If security allows, request reaches **DispatcherServlet**.
    
5.  DispatcherServlet finds the matching **controller method** based on URL + HTTP method.
    
6.  Controller executes, may call services, repositories, etc.
    
7.  Response flows back through the filter chain and out to the client.
    

All the config you wrote controls **what happens before the controller ever sees the request.**
