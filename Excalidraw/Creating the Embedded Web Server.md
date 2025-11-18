## 💻 Creating the Embedded Web Server (Tomcat)

This step is where Spring Boot transforms from a collection of configurations and Java classes into a functioning **server** capable of listening for and responding to web requests. It's the moment your application gets its own built-in hosting environment.

Here is a detailed breakdown of what happens:

---

### 1. The Decision to Build

The entire process begins because your project included the **`spring-boot-starter-web`** dependency.

* **Auto-Configuration:** Spring Boot's automatic configuration system detects this dependency and knows you intend to build a web application. It selects the default embedded server, which is **Tomcat** (though it could be Jetty or Undertow if you configured it differently).

### 2. The Factory is Created

Spring doesn't create the Tomcat server directly; it creates a blueprint for it called the **`TomcatServletWebServerFactory`**.

* **Role of the Factory:** This factory object is responsible for setting all the necessary parameters for the server, such as what port it should listen on (e.g., 8080), the context path, and how big its thread pools should be. It's the foreman in charge of server construction.

### 3. Creating the Tomcat Instance

The factory uses the settings it gathered to build and initialize the server object.

* **Embedded Tomcat:** Unlike traditional Java applications where you deploy a WAR file to a separate, already-running Tomcat server, Spring Boot creates an **embedded** instance. This means the Tomcat server is a Java object that lives and runs *inside* your main application process, making deployment much simpler.

### 4. Registering the Core Components

Once the server object exists, Spring registers the two most critical components needed to handle requests: the **DispatcherServlet** and the **Filters**.

#### A. The **`DispatcherServlet`** (The Traffic Controller)

* **What it is:** This is the single, centralized entry point for all web requests into your Spring application.
* **Action:** Spring registers this servlet with the embedded Tomcat instance. Tomcat is told: "For any request that comes in, pass it to this `DispatcherServlet`."
* **Role:** The `DispatcherServlet`'s job is to look at the URL and figure out which of your `@Controller` methods should handle that specific request. It is the core of the Spring MVC framework.

#### B. **Servlet Filters** (The Security Checkpoints)

* **What they are:** These are specialized components (like your security and rate-limiting logic) designed to intercept a request *before* it reaches the `DispatcherServlet`.
* **Action:** Spring registers these filters with Tomcat, making them part of the server's mandatory processing chain.
    * **Rate Limiter Filter:** Runs first. If the request volume is too high, it blocks the request immediately.
    * **Security Filter:** Runs next. It checks the user's credentials, verifies permissions, and manages session state.
    * This ensures that no unauthorized or malicious request ever consumes your application's core business logic.

### 5. Final Configuration

The factory performs cleanup and final settings that apply to the entire server:

* **Context Path:** Configures the base path for your application (e.g., if you set it to `/api`, all endpoints start with `/api`).
* **MIME Types/Encoding/Errors:** Sets defaults for things like character encoding (usually UTF-8) and defines which custom pages to display for errors like "404 Not Found" or "500 Internal Server Error."

### Conclusion

At the end of this step, the **Tomcat object is fully created, configured, and loaded with all its components (Filters, DispatcherServlet)**. However, it is **not yet "ready,"** because Spring still needs to finalize the entire application context (e.g., finish creating all the beans and the final wiring), after which it will start the Tomcat listener, allowing it to accept connections on the configured port. 