## 🤖 Understanding JDK Dynamic Proxy

The **JDK Dynamic Proxy** is a mechanism in Java that lets you create a **proxy class** at runtime. A proxy is essentially an object that acts as a substitute or placeholder for another object, known as the **subject** or **real object**.

Instead of writing the proxy code manually, the JDK generates it dynamically for you when the program is running. This is extremely useful for implementing generic, cross-cutting concerns (like logging, security checks, transaction management, or performance monitoring) without modifying the original subject code.

-----

## 🛠️ Key Components and How it Works

The JDK Dynamic Proxy revolves around three main parts:

### 1\. The Subject Interface (Interface)

The dynamic proxy must implement one or more **interfaces**. The proxy object will be created to appear and act exactly like an implementation of these interfaces.

  * **Example:** If you have an interface `UserService` with a method `createUser()`, the proxy will also implement `UserService` and appear to have a `createUser()` method.

### 2\. The Invocation Handler (Handler)

This is the most crucial part. The `InvocationHandler` is an interface with a single method: `invoke(Object proxy, Method method, Object[] args)`. You must create a class that implements this interface.

  * **What it does:** When any method is called on the **proxy object**, the call is **intercepted** and redirected entirely to the `invoke` method of your `InvocationHandler`.

  * **The parameters:**

      * `proxy`: The proxy instance itself (rarely used directly).
      * `method`: A `java.lang.reflect.Method` object representing the method that was called on the proxy (e.g., the `createUser()` method).
      * `args`: An array of objects representing the arguments passed to the method call.

  * **Your logic:** Inside the `invoke` method, you write the **actual logic**—the "before" and "after" processing. For example, you can print a log message *before* calling the real method, and *after* the real method returns, you can check for errors. Finally, you use **Reflection** to call the method on the **real subject object**.

### 3\. The Proxy Class Generator (Proxy)

This is the static utility class, `java.lang.reflect.Proxy`, which does the heavy lifting.

  * **The key method:** You use `Proxy.newProxyInstance(...)` to create the proxy object.
  * **What it needs:**
      * The **Class Loader** to define the new proxy class.
      * The **Interfaces** the proxy should implement.
      * Your custom **Invocation Handler** instance.

When this method is called, the JDK:

1.  Dynamically generates the bytecode for a new class that implements the specified interfaces.
2.  Creates an instance of this new class.
3.  Associates this new instance with your provided `InvocationHandler`.
4.  Returns the new proxy object to you.

-----

## 💡 Practical Application Example: Logging

Imagine you want to log every time a method is called on your `RealUserService` implementation.

### Without Dynamic Proxy (Manual Approach)

You'd have to manually add logging code to every method in `RealUserService`:

```java
public class RealUserService implements UserService {
    public void createUser() {
        // [Logging Before]
        System.out.println("LOG: Starting createUser()");
        // Real logic
        // [Logging After]
    }
}
```

### With Dynamic Proxy (AOP Approach)

You keep the `RealUserService` clean and inject the logging logic externally:

1.  **Define the Interface:**

    ```java
    public interface UserService { void createUser(); }
    ```

2.  **Define the Real Subject:**

    ```java
    public class RealUserService implements UserService {
        public void createUser() { /* actual database work */ }
    }
    ```

3.  **Define the Logging Invocation Handler:**

    ```java
    public class LoggingHandler implements InvocationHandler {
        private final Object target; // The RealUserService instance

        // Constructor to hold the real object
        public LoggingHandler(Object target) { this.target = target; }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // **BEFORE** the method runs
            System.out.println("LOG: Calling method: " + method.getName());

            // 1. Call the method on the **real** object using Reflection
            Object result = method.invoke(target, args);

            // **AFTER** the method runs
            System.out.println("LOG: Finished method: " + method.getName());

            return result;
        }
    }
    ```

4.  **Create and Use the Proxy:**

    ```java
    RealUserService realUser = new RealUserService();
    UserService proxy = (UserService) Proxy.newProxyInstance(
        UserService.class.getClassLoader(), // Class Loader
        new Class[]{UserService.class},       // Interfaces
        new LoggingHandler(realUser)        // The Handler
    );

    // When you call this, it goes to the invoke() method!
    proxy.createUser(); 
    ```

**Result:** When `proxy.createUser()` is called, your `invoke` method runs, prints the "before" log, then calls the real `createUser` method on `RealUserService`, and finally prints the "after" log.

This makes the code much cleaner and adheres to the **Open/Closed Principle** (Open for extension, closed for modification), as you can add new cross-cutting behavior without changing the core business logic.