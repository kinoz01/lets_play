> See also [[Proxies in Spring]]

## 🎭 AOP Proxy Explained

An **AOP Proxy** is a dynamically generated object created by the Spring Framework that serves as a **stand-in** for a target object, primarily to **inject cross-cutting concerns** into the application.

Essentially, when you ask Spring for a bean, if that bean has been marked for AOP processing (e.g., using `@Transactional`, `@PreAuthorize`, or custom AOP advice), Spring doesn't give you the original object; it gives you the AOP Proxy instead.

### 1. Function: Interception and Augmentation

The sole purpose of the AOP proxy is to **intercept** method calls to the target object.

* **Intercept:** When your code calls a method on the proxy, the proxy is the first to receive the call.
* **Augment:** Before passing the call to the original object (the target), the proxy executes the necessary AOP logic (the **Advice**), such as starting a timer, checking security permissions, or starting a transaction.
* **Delegate:** Finally, the proxy passes the control to the actual method on the target object.

### 2. The Core Difference

While **"proxy"** is a general software engineering term for any object that controls access to another, an **"AOP proxy"** is specific to Spring and always exists to perform **Advice** (AOP logic).

| Feature | General Proxy | AOP Proxy (in Spring) |
| :--- | :--- | :--- |
| **Purpose** | Control access, limit resource usage, simplify object creation (e.g., *Repository Proxy*). | **Inject Cross-Cutting Concerns** (Transaction, Security, Logging). |
| **Trigger** | Any design requirement (e.g., the code uses an interface). | The presence of an **AOP Annotation** (`@Transactional`) or **Aspect definition**. |

### 3. Creation Mechanisms

Spring uses two primary techniques to generate AOP proxies dynamically at runtime, as defined by the target object:

#### A. JDK Dynamic Proxies
* **Used when:** The target class implements one or more **interfaces**.
* **How it works:** Spring generates a new class in memory that implements the same interfaces as the target. Since Java interfaces are involved, this is Spring's preferred default method.

#### B. CGLIB Proxies
* **Used when:** The target class **does not implement an interface** or you explicitly configure Spring to use CGLIB.
* **How it works:** CGLIB (Code Generation Library) creates a **subclass** of the target class. This subclass overrides the methods you are advising and inserts the AOP logic before calling the `super` method (the original logic). This is why CGLIB proxies require the target class and its methods to *not* be declared `final`.

### 4. Example: The `@Transactional` AOP Proxy

When you annotate a service method with `@Transactional`, here is the proxy flow:

1.  **Your code calls:** `userService.saveUser(user)`.
2.  **The AOP Proxy intercepts:** The proxy receives the call.
3.  **The Advice executes (Before):** The proxy executes the transaction advice, initiating a database transaction.
4.  **Delegation:** The proxy forwards the call to the actual `UserService.saveUser(user)` method.
5.  **The Advice executes (After):** The proxy receives the return, executes the transaction advice again, and either **commits** or **rolls back** the transaction based on the outcome.

The AOP Proxy is the glue that seamlessly weaves the transaction management logic into your core business method.