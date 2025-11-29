
The statement—**"extending `RuntimeException` means they are unchecked (you don't have to declare them in method signatures)"**—refers to how the Java compiler treats exceptions based on their position in the exception hierarchy.

Here's a detailed explanation:

---

## 1. 🌳 The Java Exception Hierarchy

In Java, all throwable objects inherit from the base class `Throwable`. This tree is divided into two main branches: **`Error`** and **`Exception`**. The `Exception` branch is further divided into two types:

|**Exception Type**|**Parent Class**|**When to Use**|
|---|---|---|
|**Checked Exceptions**|Directly extend **`Exception`** (but not `RuntimeException`).|For **predictable but recoverable** problems that external factors cause (e.g., file not found, I/O failure).|
|**Unchecked Exceptions**|Extend **`RuntimeException`** or **`Error`**.|For **unpredictable, programming-related errors** (e.g., null pointer access, index out of bounds, or business rule violations).|

---

## 2. 📝 The "Checked" Rule (Compiler Enforcement)

**Checked exceptions** enforce the "handle or declare" rule at **compile time**.

- **Rule:** If a method throws a checked exception, the method **must** either:
    
    1. **Catch it** using a `try-catch` block.
        
    2. **Declare it** using the `throws` keyword in the method signature.
        

### Example with a Checked Exception (`IOException`)


```java
// IOException is a checked exception.
public void readFile() throws IOException { // 👈 MUST declare it
    // Code that might throw IOException
}
```

If you forget the `throws IOException` part, the Java compiler **will not let the code compile**.

---

## 3. 👻 The "Unchecked" Freedom (Why `RuntimeException` is Used)

**Unchecked exceptions** (like your custom ones extending `RuntimeException`) **do not** have to be declared in the method signature. This gives you freedom from the "handle or declare" rule.

- **Rule:** The compiler ignores them. You **can** catch them, but you are **not required** to declare them.
    

### Example with your Custom Unchecked Exception

```java
public class ResourceNotFoundException extends RuntimeException { ... }

// A method in your Service Layer:
public Product getProduct(Long id) {
    Product p = productRepository.findById(id);
    if (p == null) {
        throw new ResourceNotFoundException("Product not found"); // 👈 Can throw it freely
    }
    return p;
}
```

Notice that the `getProduct` method signature **does not** include `throws ResourceNotFoundException`. The code compiles fine because it's an unchecked exception.

### Why this is essential for REST APIs

In a Spring REST API using a **Global Exception Handler**, this freedom is crucial:

- **Cleaner Code:** It keeps your service and controller methods focused purely on business logic, without being cluttered by repetitive `throws` clauses for every potential business failure.
    
- **Automatic Propagation:** The unchecked exception is allowed to automatically "bubble up" the call stack until it reaches the Spring framework, which then directs it to your **`@RestControllerAdvice`**. This is why your global error handling pattern works so cleanly.