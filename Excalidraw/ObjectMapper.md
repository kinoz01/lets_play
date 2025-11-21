## 🧐 What is `ObjectMapper`?

The `ObjectMapper` is a class provided by the **Jackson library**, which is the default library Spring Boot uses for handling JSON data.

Its primary job is to act as a **translator** between two different formats:

1. **Java Objects:** The structured data you define in your Java code (like your `ApiError` class).
    
2. **JSON (JavaScript Object Notation):** The universal, text-based format used for sending data over the internet.
    

### The Two Main Operations

The `ObjectMapper` performs two crucial operations:

|**Operation**|**Action**|**Example (Your Code)**|
|---|---|---|
|**Serialization**|Translating a **Java Object** into a **JSON String**.|`objectMapper.writeValueAsString(error)`|
|**Deserialization**|Translating a **JSON String** into a **Java Object**.|(Used when an external system sends JSON to your controller)|

---

## 🛠️ How it Works in Your Filter

In your `RateLimitingFilter`, the `ObjectMapper` is used specifically for **serialization** to send a clear error message back to the client when the rate limit is exceeded.

### The Steps:

1. **The Java Object is Created:**
    
    
    ```java
    ApiError error = new ApiError(
        HttpStatus.TOO_MANY_REQUESTS.value(), 
        "Too Many Requests",
        "Rate limit exceeded...", 
        request.getRequestURI()
    );
    ```
    
    You create a structured Java object (`error`) containing all the details about the failure (status code, message, path, etc.).
    
1. **Serialization Occurs:**
    
    ```java
    response.getWriter().write(objectMapper.writeValueAsString(error));
    ```
    
    - The `objectMapper.writeValueAsString(error)` method takes the **`error`** Java object.
        
    - It looks at all the fields and values in the `ApiError` class (like `status`, `message`, `path`).
        
    - It then converts this structure into a single, standard **JSON text string**.
        
2. The JSON is Sent:
    
    The resulting JSON string (the text) is written directly to the HTTP response body and sent back to the client (e.g., a web browser or a mobile app).
    

### Example Translation:

If your `ApiError` object looked like this in Java memory:

|**Field**|**Value**|
|---|---|
|`status`|429|
|`message`|"Too Many Requests"|
|`path`|"/api/products"|

The `ObjectMapper` converts it into this final JSON text string, which is what the client receives:

```json
{
  "status": 429,
  "message": "Too Many Requests",
  "path": "/api/products"
}
```

The client (or their frontend code) can easily read and understand this JSON format.