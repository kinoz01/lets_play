This example demonstrates how an Aspect (the cross-cutting concern) can run code before and after a method's execution without changing the method itself.

---

## 🚀 Example: Performance Monitoring Aspect

Imagine you have a core service method, `calculateOrderTotal`, and you want to know exactly how long it takes to run, but you don't want to clutter the method with timing code.

### 1. The Core Business Logic (The Target)

This is the method we want to monitor.


```java
// File: OrderService.java (The Target Class)
@Service
public class OrderService {

    public double calculateOrderTotal(String userId) {
        // Simulate a time-consuming database operation or complex calculation
        try {
            Thread.sleep(150); // Takes 150 milliseconds
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // Core business logic...
        return 125.50;
    }

    public void placeOrder(String userId, double total) {
        // Simple, fast logic...
        System.out.println("Order placed for user: " + userId + " with total: " + total);
    }
}
```

### 2. The Aspect (The Cross-Cutting Concern)

We'll create an Aspect using **`@Around` Advice**, which is the most powerful type, allowing us to control the execution of the target method and capture the start/end time.

```java
// File: TimingAspect.java (The Aspect)
@Aspect
@Component
public class TimingAspect {

    // 1. Pointcut: Defines WHERE to apply the advice.
    // This selects all methods named 'calculateOrderTotal' in the OrderService class.
    @Pointcut("execution(* com.example.service.OrderService.calculateOrderTotal(..))")
    public void timingPointcut() {}

    // 2. Advice: Defines WHAT to do and WHEN to do it.
    @Around("timingPointcut()")
    public Object profile(ProceedingJoinPoint joinPoint) throws Throwable {

        // --- Logic BEFORE the target method execution ---
        long startTime = System.currentTimeMillis();
        String methodName = joinPoint.getSignature().getName();
        System.out.println(">> AOP: START timing for method: " + methodName);

        // --- Execute the Target Method ---
        // This line runs the actual OrderService.calculateOrderTotal(userId) method
        Object result = joinPoint.proceed();

        // --- Logic AFTER the target method execution ---
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;

        System.out.println("<< AOP: END timing for method: " + methodName +
                           ". Execution took " + duration + "ms.");
        
        // Return the result of the target method
        return result;
    }
}
```

---

## 3. 🖥️ What Happens at Runtime (The Output)

When you call `orderService.calculateOrderTotal("user123")` from your main application, the Spring container intercepts the call and inserts the Aspect's logic:

**Output:**

```
>> AOP: START timing for method: calculateOrderTotal
Order placed for user: user123 with total: 125.5
<< AOP: END timing for method: calculateOrderTotal. Execution took 152ms.
```

### Explanation of the Process:

|**AOP Term**|**Example in Code**|**Description**|
|---|---|---|
|**Aspect**|`TimingAspect` class|The modular unit that handles the **Performance Monitoring** concern.|
|**Advice**|The `profile` method|The **logic** (setting timers, logging the result) that runs _around_ the target method.|
|**Pointcut**|`execution(* ...calculateOrderTotal(..))`|The **rule** that specifies _only_ the `calculateOrderTotal` method should be timed.|
|**Join Point**|The moment the `calculateOrderTotal` method is called.|The **opportunity** where the Advice is plugged in.|
|**Target Object**|The `OrderService` instance|The object whose method is being advised (monitored).|
|**`joinPoint.proceed()`**|Inside the `profile` method|This instruction tells the Advice to **execute the original target method**.|

**In summary:** The **Aspect** allowed you to add complex timing logic to the service method **without ever touching the `OrderService.java` file**, keeping the core business logic clean and focused. This separation is the primary benefit of AOP.