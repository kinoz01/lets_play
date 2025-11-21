Every filter must explicitly tell the chain to proceed. This is done by calling the single, critical method on the chain object:

$$\text{filterChain.doFilter(request, response);}$$

- **Calling `doFilter()`** tells the servlet container: "I am finished with this request. Please send it to the **next component** in the line."
    
- If a filter **does not call** `doFilter()`, the request stops at that filter, and the application must send a response (e.g., a **429 Too Many Requests** or a **403 Forbidden**) immediately. If no response is sent, the connection will simply time out.
    
### Two-Way Journey

The `FilterChain` controls both the **request flow** and the **response flow**:

|**Phase**|**Direction**|**Action**|
|---|---|---|
|**Request Processing**|**Inbound** (Filter 1 $\rightarrow$ Filter 2 $\rightarrow$ DispatcherServlet)|Each filter processes the request, potentially modifying it (e.g., changing headers) or blocking it.|
|**Response Processing**|**Outbound** (DispatcherServlet $\rightarrow$ Filter 2 $\rightarrow$ Filter 1)|After the Controller returns a result, the response travels back through the filters in **reverse order**. Filters can inspect the response (e.g., calculate processing time) or modify the response (e.g., add CORS headers).|

### Implementation Details

- **Creation:** The `FilterChain` object is **created and managed by the Servlet Container (Tomcat)** at runtime. It's an internal object that contains a pointer to the next component that needs to be executed.
    
- **Usage in Spring:** In your Spring application, the `FilterChain` object is passed into your `doFilterInternal` method as an **argument**. This keeps the control flow tightly integrated with the low-level web server mechanics.


---

## 🛠️ FilterChain: Under the Hood

The `FilterChain` is not a simple list; it is a smart, stateful object created by the Servlet container to manage the flow of control and ensure that every registered filter runs in the correct order.

### 1. The Hidden Object: The `ApplicationFilterChain`

When Tomcat (or any other servlet container) receives an HTTP request, it follows these steps:

1. **Registration:** The container reads the application configuration (which Spring has assembled for it) and creates an ordered, internal array or list of all `Filter` instances (e.g., Security Filter, your `RateLimitingFilter`, Logging Filter, etc.).
    
2. **Creation:** The container instantiates a special class, often named something like **`ApplicationFilterChain`** (the concrete implementation of the `FilterChain` interface).
    
3. **State Management:** This `ApplicationFilterChain` object is initialized with two critical pieces of internal state:
    
    - An **internal pointer/index** that starts at 0.
        
    - A **reference to the array** of all registered filters.
        

### 2. The Core Function: `doFilter(request, response)`

The magic of control flow happens entirely inside the `ApplicationFilterChain` object's `doFilter` method.

When your code executes `filterChain.doFilter(request, response);`, here is the **exact, sequential process** that occurs within the container:

|**Step**|**Action**|**Description**|
|---|---|---|
|**A. Check Index**|The `doFilter` method checks the current value of its **internal index**. This index tells the chain where it last left off.||
|**B. Boundary Check**|If the index is less than the total number of filters, it means there are **more filters** to run.||
|**C. Get Next Filter**|The method retrieves the `Filter` instance (e.g., the Security Filter) located at the current index position from its internal array.||
|**D. Increment Index**|**CRITICAL STEP:** The chain object **increments its internal index** by one. This ensures that the _next_ time `doFilter` is called, it will point to the _following_ filter, not the current one.||
|**E. Execute Filter**|The chain calls the target filter's method: `nextFilter.doFilter(request, response)`. This transfers control to the next filter in the assembly line.||
|**F. Final Destination (The Servlet)**|If the index check (Step B) reveals that there are no more filters left, the `doFilter` method knows it has reached the end of the line. It **transfers control to the final component**, which is usually the **DispatcherServlet** in a Spring application.||

### 3. The Two-Way Flow Under the Hood

The flow of execution is entirely dependent on where the `filterChain.doFilter()` call is placed within a filter's code.

|**Location of doFilter()**|**Effect on Execution**|
|---|---|
|**Before `doFilter()`**|This code executes on the **Inbound Request**. (Example: Your rate limiter runs here to inspect the request IP before proceeding).|
|**After `doFilter()`**|This code executes on the **Outbound Response**. The call to `doFilter()` returns only after the Controller has run and the response has started traveling back up the chain. (Example: A logging filter runs here to record the final HTTP status code and latency).|

If your `RateLimitingFilter` blocks the request (sends the 429 error), it never calls `filterChain.doFilter()`, meaning the index is never incremented, and the request never moves to the next component. .