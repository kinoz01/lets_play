## 📌 **What This Controller Is**

`AuthController` is a **REST API controller** responsible for user authentication and account management:

-   **Register new users**
    
-   **Login and receive JWT**
    
-   **Get the authenticated user’s profile**
    

It delegates all business logic to `AuthService`.

---

## 📦 **Class-Level Annotations**

### `@RestController`

A shorthand for:

-   [[@Controller]]
    
-   `@ResponseBody`
    

This means:

-   The class handles HTTP requests
    
-   All returned objects are automatically converted to JSON (via Jackson)
    

---

### `@RequestMapping("/api/auth")`

All endpoints in this controller will have the path prefix:

```bash
/api/auth/...
```

So:

-   `register` → `/api/auth/register`
    
-   `login` → `/api/auth/login`
    
-   `me` → `/api/auth/me`
    

---

## 🔧 **Constructor Injection**

```java
public AuthController(AuthService authService) {
    this.authService = authService;
}
```

Spring automatically instantiates the controller and injects `AuthService`.

**Best practice**: Constructor injection is the recommended way in Spring.

---
## 🔐 Security Annotations

### `@PermitAll`

This annotation (from `jakarta.annotation.security`) means:

> Allow anyone to call this endpoint — no authentication required.

You use this on:

-   `/register`
    
-   `/login`
    

This is correct because users cannot register or login if authentication is required.

---

### `@PreAuthorize("isAuthenticated()")`

Spring Security checks the expression **before the method is called**.

`isAuthenticated()` means:

> Only allow this endpoint if a valid Authentication object exists  
> (from your JWT filter).

Used on `/me`.

If the JWT is invalid / missing → the request is denied **before** the method is executed.

---

## Method-Level Breakdown


## 1️⃣ **Register Endpoint**

```java
@PostMapping("/register")
@PermitAll
public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
    return ResponseEntity.ok(authService.register(request));
}
```

The method is defined as: `public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request)`

Let's break down every part:

- **`@PostMapping("/register")`**: This is a Spring Web annotation that maps **HTTP POST requests** to this specific method. When a client sends a POST request to the path `/register` (relative to the base path of the controller), this method will be executed. POST is the standard HTTP verb used for creating new resources, such as a new user account.
    
- **`@PermitAll`**: This annotation is typically used in conjunction with Spring Security. It configures the security filter chain to allow **unauthenticated and unauthorized access** to this specific endpoint. In the context of registration, this is essential because a user must be able to register _before_ they have an account or can be authenticated. 
  **Recommendation:** If you are using Spring Security's method-level security (enabled by `@EnableMethodSecurity(prePostEnabled = true)`), the recommended way to achieve this is by using the [[Spring Expression Language (SpEL)]] equivalent: **`@PreAuthorize("permitAll()")`**.
    
- **`public ResponseEntity<AuthResponse>`**: This is the method's return type.
    
    - **`public`** means the method can be accessed from any other class.
        
    - **`ResponseEntity<T>`** is a Spring class that represents the entire **HTTP response**, including the status code, headers, and body. Using it allows the developer to precisely control the response sent back to the client.
        
    - **`<AuthResponse>`** is a [[generic]] type parameter, indicating that the body of the HTTP response will contain an object of the custom class `AuthResponse`. This class likely holds information relevant after a successful registration, such as a JWT (JSON Web Token) and/or user details.
        
- **`register`**: This is the name of the method.
    
- **`(@Valid @RequestBody RegisterRequest request)`**: This defines the method's single parameter.
    
    - **`@RequestBody`**: This Spring annotation tells Spring to automatically deserialize the **HTTP request body** (which is expected to be in JSON format) into an instance of the `RegisterRequest` class. This is where the client sends the registration data (e.g., username, email, password).
        
    - **`@Valid`**: This is a standard Bean Validation annotation (from the Jakarta Bean Validation specification, often implemented by Hibernate Validator). It instructs Spring to validate the `RegisterRequest` object **immediately** after it has been deserialized. The `RegisterRequest` class will have constraints defined on its fields (e.g., `@NotBlank` on the username, `@Email` on the email field, `@Size` on the password). If any of these constraints are violated, the method will not execute, and Spring will automatically send a **400 Bad Request** response to the client.
        
    - **`RegisterRequest request`**: This is the actual parameter, an object of the custom class `RegisterRequest` which encapsulates the user's registration input.
        
- **`{ return ResponseEntity.ok(authService.register(request)); }`**: This is the method body, containing the core logic.
    
    - **`authService.register(request)`**: This is a method call to a service layer component, typically named `AuthService`. The `request` object (containing the registration data) is passed to it. This service method is responsible for the actual business logic of registration:
        
        1. Hashing the password (security measure).
            
        2. Checking if a user with the provided email/username already exists.
            
        3. Saving the new user entity to the database.
            
        4. Generating an authentication token (like a JWT) if the design requires the user to be logged in immediately after registration.
            
        5. It returns an `AuthResponse` object upon successful completion.
            
    - **`ResponseEntity.ok(...)`**: This is a static factory method that creates a `ResponseEntity` object.
        
        1. **`ok()`** specifically sets the HTTP status code to **200 OK**, signifying that the request was successfully processed and a response body is included.
            
        2. The `AuthResponse` object returned from the `authService.register()` call is placed into the body of this 200 OK response.
            

In summary, this method serves as the **public entry point** for user registration. It receives JSON data, validates it, delegates the complex creation and saving process to a dedicated service, and returns a successful HTTP response (200 OK) containing the necessary authentication details back to the client.

---

## 2️⃣ **Login Endpoint**

```java
@PostMapping("/login")
@PermitAll
public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
    return ResponseEntity.ok(authService.authenticate(request));
}
```

Similar flow:

1.  User sends email/password
    
2.  Validation is applied
    
3.  `authService.authenticate(request)` checks credentials, issues a JWT.
    
4.  Response contains:
    
    -   token
        
    -   possibly user role
        
    -   token expiration
        

---

## 3️⃣ **Get Current User Profile**

```java
@GetMapping("/me")
@PreAuthorize("isAuthenticated()")
public ResponseEntity<UserResponse> me() {
    return ResponseEntity.ok(authService.getCurrentUserProfile());
}
```

### Flow:

1.  A logged-in user sends `GET /api/auth/me`
    
2.  Your `JwtAuthenticationFilter` parses the JWT:
    
    -   validates signature
        
    -   extracts userId/email
        
    -   loads user from DB
        
    -   creates `Authentication` object
        
3.  `@PreAuthorize("isAuthenticated()")` ensures:
    
    -   user is authenticated
        
    -   otherwise returns 401/403 *before method runs*
        
4.  `authService.getCurrentUserProfile()`:
    
    -   extract current principal from SecurityContext
        
    -   return user data as `UserResponse`
        


### 🎯 Why This Controller Is Good (Best Practices)

✔ **Constructor injection**  
✔ **Clear responsibility (thin controller, logic in service)**  
✔ **DTO usage for input**  
✔ **Validation with `@Valid`**  
✔ **Security annotations applied appropriately**  
✔ **Separation of “public” and “protected” endpoints**  
✔ **JWT-ready design**

This is aligned with official Spring Security guidelines (Spring Boot 3 / Spring 6).
