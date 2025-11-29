We could use directly:

```java
UserDetails userDetails = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
```

But that's bad practice:

## 1. Decoupling Security from Persistence (Why not use the repository directly)

If your `JwtAuthenticationFilter` directly used the `UserRepository` to fetch the user:


```java
// What you are suggesting (A BAD PRACTICE)
User user = userRepository.findByEmail(email); 
// Filter directly accessing the database layer
```

- **Tight Coupling:** Your security filter becomes tightly coupled to the persistence implementation (e.g., Spring Data JPA, MongoDB, etc.). If you ever switch from MongoDB to PostgreSQL, you have to rewrite security code.
    
- **Missing Business Logic:** Repositories return raw domain objects (`User`). However, the process of loading a user might involve additional business checks (e.g., checking if the user is enabled, calculating dynamic authorities, or handling multi-tenancy). This logic belongs in the service layer, not the filter.
    
- **Violates Layered Architecture:** The filter is part of the **Web/Security Layer**. It should not reach directly into the **Persistence Layer**. It should only talk to the **Service Layer** (where `UserDetailsService` typically lives).
    

---

## 2. The Role of `UserDetailsService` (The Contract)

The `UserDetailsService` interface acts as the necessary **abstraction layer** between the security mechanism and your application's data layer.

### A. The Spring Security Contract

The `UserDetailsService` interface has only one required method:


```java
public interface UserDetailsService {
    // The contract: Given a username, I must return a fully loaded UserDetails object.
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

- **Guiding Principle:** Spring Security does not care _how_ you load the user (from a database, an LDAP server, a cache, a file, etc.). It only cares that you provide an implementation of this interface that returns a valid `UserDetails` object.
    

### B. The Implementation (Where the Repository Lives)

In your application, you must provide a class that implements this contract. This is where the repository is correctly used:

```java
// Example of your CustomUserDetailsService implementation
@Service
public class CustomUserDetailsService implements UserDetailsService {

    // 1. Dependency: Inject the Repository here (Service talks to Repository)
    private final UserRepository userRepository; 

    // Constructor injection...

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // 2. Logic: Use the Repository to fetch the domain object
        User user = userRepository.findByEmail(email)
                      .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        
        // 3. Mapping: Convert your domain object (User) to the Security contract (UserDetails)
        return new CustomUserDetails(user); // Assuming CustomUserDetails implements UserDetails
    }
}
```


By injecting the **`UserDetailsService`** (the service layer component) into your filter, you achieve clean separation:

- **Filter:** Focuses on tokens and security context.
    
- **Service (`UserDetailsService`):** Focuses on fetching the user and preparing the data for security.
    
- **Repository:** Focuses only on database communication.
    

This layering makes your system robust, maintainable, and easy to modify when business logic or persistence technologies change.