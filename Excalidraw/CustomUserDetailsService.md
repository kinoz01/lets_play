This class, **`CustomUserDetailsService`**, is the essential bridge that connects your application's user data (stored in MongoDB via the `UserRepository`) to the entire authentication and authorization engine of **Spring Security**.

You can't call `userRepository.findByEmail(username)` directly in the authentication process because Spring Security requires a standardized, decoupled contract to retrieve user details, and that contract is the **`UserDetailsService` interface**.

---

## 1. 🔑 The Big Picture: Decoupling and Standardization

### A. Why We Need the `UserDetailsService` Interface

Spring Security is designed to be database-agnostic. It doesn't care if your users are stored in MongoDB, PostgreSQL, LDAP, or an in-memory map. To achieve this flexibility, it relies on a standard interface: **`UserDetailsService`**.

- **Contract:** This interface has only one core method: `UserDetails loadUserByUsername(String username)`.
    
- **Role:** The purpose of this interface is to act as a **factory** for **`UserDetails`** objects. It standardizes the process of fetching user authentication data, separating the security logic from the data persistence logic.
    

### B. The Role of Your Class

By implementing this interface, your `CustomUserDetailsService` fulfills that contract and tells Spring Security exactly _how_ to load user data from _your specific source_ (MongoDB).

## 2. ⚙️ Under the Hood: The Authentication Flow

Here's a step-by-step breakdown of what happens during a login attempt and why your class is indispensable:

### Step 1: Request Submission

A user submits their email (which you use as the username) and password to the `/login` endpoint.

### Step 2: Authentication Manager

The **Authentication Manager** receives the request and delegates it to the configured **Authentication Provider** (specifically, the `DaoAuthenticationProvider`, which handles username/password credentials).

### Step 3: The `DaoAuthenticationProvider`

The `DaoAuthenticationProvider` has two primary jobs:

1. **Retrieve User Details:** It must retrieve the stored, hashed password and the user's roles from the database.
    
2. **Compare Credentials:** It must compare the stored hashed password with the hash of the password the user just submitted.
    

### Step 4: Invoking Your Custom Service (Job 1)

For Job 1 (Retrieving Details), the `DaoAuthenticationProvider` **does not** call your `UserRepository` directly. Instead, it calls the standardized method:

$$\text{authenticationProvider.getUserDetailsService().loadUserByUsername(email)}$$

This call directs the flow to **your specific implementation**:


```java
// Inside CustomUserDetailsService.loadUserByUsername()
return userRepository.findByEmail(username) // <-- Connects to MongoDB
    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
```

### Step 5: Returning the `UserDetails`

Your service fetches your custom `User` object (which implements `UserDetails`) from the database and returns it. This object contains the stored **hashed password** and the user's **authorities (roles)**.

### Step 6: Password Verification (Job 2)

The `DaoAuthenticationProvider` now has the user-submitted password (unhashed) and the stored password (hashed, retrieved from your `User` object). It passes both to the configured **`PasswordEncoder`** to perform a secure comparison.

## 3. 🎯 Why Not Call the Repository Directly?

If you were to try and call `userRepository.findByEmail(...)` directly in the login controller, you would have to manually implement all the complex logic handled by Spring Security:

1. You'd have to manually inject the **`PasswordEncoder`**.
    
2. You'd have to manually retrieve the **hashed password**.
    
3. You'd have to manually call the **`matches()`** method for comparison.
    
4. You'd have to manually create the **`UsernamePasswordAuthenticationToken`**.
    
5. You'd have to manually set the token in the **`SecurityContextHolder`**.
    

By implementing `UserDetailsService`, you only handle the **data retrieval** step. You let Spring Security's pre-built, heavily tested, and highly secure **`DaoAuthenticationProvider`** handle the remaining, critical steps of password comparison and setting the security context. This is the essence of dependency inversion and decoupling in framework design.