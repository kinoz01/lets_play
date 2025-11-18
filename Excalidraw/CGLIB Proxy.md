 **CGLIB proxy** is a specific type of **dynamic proxy** used in Java that creates a stand-in (a "proxy") for a specific class to intercept and augment its methods at runtime.

It's most often used in frameworks like **Spring** and **Hibernate** for features like transaction management, security checks, and lazy loading without forcing the original class to implement an interface.

---

## 🛠️ How CGLIB Proxy Works

-----> Reminder about [[extends & implements]] before continuing.

Think of a CGLIB proxy as creating a **smart, invisible twin** of your original class.

1.  **Code Generation Library (CGLIB):** CGLIB stands for **Code Generation Library**. It's a powerful third-party library that uses a technique called **bytecode manipulation**. This means it can generate new Java classes *after* your program has been compiled and is running.
2.  **Subclassing (Inheritance):** When you ask CGLIB to create a proxy for your class (let's call it `TargetClass`), CGLIB doesn't create a new class implementing the `TargetClass`'s interfaces (like a JDK Dynamic Proxy would). Instead, it **dynamically generates a new class** that *extends* the `TargetClass`. The generated class is a **subclass** of your original class.
3.  **Method Interception:** In this newly generated subclass (the proxy), CGLIB **overrides all the non-final methods** of the `TargetClass`. The overridden methods contain extra logic, known as an **interceptor** or **advice**.
4.  **The Interceptor:** When you call a method on the CGLIB proxy object, the call is first routed to the interceptor logic. The interceptor can do things like:
    * Start a database transaction *before* calling the original method.
    * Check for user permissions *before* calling the original method.
    * Log the method execution time *before* and *after* calling the original method.
    * Only *then* does the interceptor call the original method on the superclass (`TargetClass`) using a special `invokeSuper` mechanism.

The key takeaway is that the object you interact with is the **subclass proxy**, not the original class instance, but it behaves exactly like the original object, with added functionality around the methods.

---

## 🆚 CGLIB vs. JDK Dynamic Proxy

In Java, there are two primary ways to create dynamic proxies, and they differ mainly in what they can proxy:

| Feature | CGLIB Proxy | JDK Dynamic Proxy |
| :--- | :--- | :--- |
| **Mechanism** | **Subclassing** (Inheritance) | **Interface Implementation** |
| **Requirement** | Can proxy **classes** directly. **No interface is required.** | Can only proxy classes that implement at least one **interface**. |
| **Limitations** | **Cannot** proxy `final` classes or `final` methods (because they cannot be extended/overridden). | Can only proxy methods defined in the interface(s). |
| **Dependency** | Requires the external **CGLIB** library (though often repackaged inside frameworks like Spring). | Built into the standard **Java Development Kit (JDK)**. |

### When is CGLIB used?

Frameworks typically default to the simpler [[JDK Dynamic Proxy]] if the target class implements an interface. However, if the class you want to proxy **does not implement any interfaces** (it's a concrete class), then CGLIB is used because the JDK's proxy mechanism cannot work without an interface.

---

## 🛑 Important Limitation: Final Classes/Methods

Since CGLIB works by creating a **subclass** and **overriding** methods, it **cannot** be used to proxy classes or methods marked as `final`.

* A **`final` class** cannot be extended.
* A **`final` method** cannot be overridden.

This is a crucial point to remember when developing Java applications with frameworks that rely on CGLIB.