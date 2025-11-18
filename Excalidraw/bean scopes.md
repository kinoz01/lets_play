## 🔭 Understanding Bean Scopes

When Spring manages a bean, it needs to know if it should create one single object for the entire application, or a new object every time it's requested. The scope tells the container how to manage this.

There are five primary scopes, categorized into standard and web-aware scopes:

-----

### 1\. Standard Scopes (Available in all Spring Applications)

#### 🥇 Singleton (The Default)

  * **Behavior:** Only **one single instance** of the bean is created per Spring IoC container. This is the **default scope** and the most common.
  * **Life Cycle:** The instance is created when the container starts and persists until the container is shut down.
  * **Use Case:** This is ideal for stateless services like `UserService`, `EmailService`, or `Repository` classes, where having only one shared instance is efficient and sufficient. All requests share this same object.

> **Example:** You have a calculator service. Everyone uses the same calculator object; it doesn't need to be unique for each user.

#### 🥈 Prototype

  * **Behavior:** A **new instance** of the bean is created **every time** it is requested (i.e., when another bean asks for it via injection, or when you explicitly ask the container for it).
  * **Life Cycle:** Spring manages the creation, but it **does not** manage the subsequent lifecycle (e.g., destruction) of the prototype object. Once created, it's up to the client code to handle it.
  * **Use Case:** Use this for stateful objects that need to maintain unique data or state for each client or operation, such as objects representing a database connection or a shopping cart.

> **Example:** Every customer needs their own unique shopping cart object to hold their items.

-----

### 2\. Web-Aware Scopes (Only Available in Web Applications)

These scopes require a web-aware Spring ApplicationContext (like `WebApplicationContext`).

#### 🌐 Request

  * **Behavior:** A **new instance** of the bean is created for **each incoming HTTP request**.
  * **Life Cycle:** The instance is destroyed once the request finishes (it's visible only during the processing of that single request).
  * **Use Case:** Holding request-specific data, like input forms or a transaction ID that needs to be unique to a single web request.

#### 🗃️ Session

  * **Behavior:** A **single instance** of the bean is created for **each HTTP session**.
  * **Life Cycle:** The instance lives for the duration of the user's session and is destroyed when the session expires or is invalidated.
  * **Use Case:** Storing user-specific information that persists across multiple requests, like a logged-in user's details or their preferred language.

#### 🌍 Application

  * **Behavior:** A **single instance** of the bean is created for the **entire web application** (similar to Singleton, but scoped specifically to the `ServletContext`).
  * **Life Cycle:** The instance is created when the web application starts and lives until the web application is shut down.
  * **Use Case:** Storing global application configuration or counters.

-----

## 💻 How to Define a Bean's Scope

You specify the scope using the `@Scope` annotation alongside the bean definition annotation (like `@Component` or `@Bean`).

```java
// Default scope (Singleton) - No @Scope annotation needed, but can be added for clarity
@Service
@Scope("singleton") // This is implied if omitted
public class EmailService { ... } 
```

```java
// Prototype scope - A new instance every time it's injected
@Component
@Scope("prototype") 
public class ShoppingCart { ... }
```

```java
// Request scope - A new instance for every HTTP request
@Component
@Scope("request") 
public class RequestTracker { ... }
```

---