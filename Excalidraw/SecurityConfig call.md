Here is the breakdown of **When** it is called, **Who** calls it, and **Why** the constructor is important.

### 1. When and Who calls `SecurityConfig`?

- **When:** Immediately when your application starts up (during the "Bootstrap" phase).
    
- **Who:** The **Spring Application Context** (specifically the Spring Container).
    

**The Process:**

1. **Scanning:** When you run your app (e.g., `SpringApplication.run(...)`), Spring scans your classpath for any class annotated with `@Configuration`.
    
2. **Detection:** It finds your `SecurityConfig` class.
    
3. **Instantiation:** Spring essentially performs `new SecurityConfig()` internally.
    
4. **Bean Creation:** Once the class is instantiated, Spring looks for methods inside it annotated with `@Bean` (like your `securityFilterChain`) and executes them to configure the security system.
    

> **Note:** This happens only **once** per application run. The class is a "Singleton" bean.

---

### 2. What do we do with its Constructor?

The constructor is the correct place to **inject dependencies** that your security rules need to function. This is known as "**Constructor Injection**" and is the industry standard (preferred over using `@Autowired` on fields).

**Common things to inject in the Constructor:**

- **`UserDetailsService`:** If you have custom logic to load users from a database.
    
- **`JwtUtils` / `TokenProvider`:** If you are doing stateless authentication (JWT).
    
- **`CorsConfigurationSource`:** If you have complex CORS rules defined elsewhere.
    
- **`UnauthorizedHandler`:** Custom logic for handling 401 errors.
    

#### Why use the Constructor?

- **Immutability:** You can mark the fields as `final`, ensuring they are never changed once the security config is loaded.
    
- **Safety:** It ensures that your Security Config _cannot_ be created unless these required tools are present.