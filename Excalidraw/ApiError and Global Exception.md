## ⚙️ Role of the Global Exception Handler (Controller Advice)

The `ApiError` class doesn't handle errors itself; it's just the **data structure** for the response. The actual error interception and formatting is done by a specialized Spring component, usually a class annotated with `@ControllerAdvice` or `@RestControllerAdvice`.

### 1. The `@RestControllerAdvice` Component

A class annotated with `@RestControllerAdvice` acts as a **global exception interceptor** for all controllers in your application.

- It allows you to centralize error handling logic, meaning you don't have to write `try-catch` blocks in every controller method.
    
- By using methods annotated with **`@ExceptionHandler`**, this class listens for specific types of exceptions thrown anywhere in the application (controllers, services, repositories).
    

### 2. How an Exception is Converted to an `ApiError`

When an error occurs (e.g., a resource isn't found, or validation fails), the process typically follows these steps:

1. **Exception Thrown** 💥: A method (e.g., in the `UserService`) throws an exception, such as `ResourceNotFoundException`.
    
2. **Interception** 🎣: The `@RestControllerAdvice` component intercepts this exception.
    
3. **Specific Handler Invoked** ✨: A method within the advice class, annotated with `@ExceptionHandler(ResourceNotFoundException.class)`, is executed.
    

---

## 📝 Example Handler Method

Here is what a handler method inside the `@RestControllerAdvice` might look like for a common error:


```java
// Inside a class annotated with @RestControllerAdvice
@ExceptionHandler(ResourceNotFoundException.class)
public ResponseEntity<ApiError> handleNotFoundException(ResourceNotFoundException ex, WebRequest request) {
    // 1. Determine HTTP Status Code
    int status = HttpStatus.NOT_FOUND.value(); // 404

    // 2. Build the ApiError DTO
    ApiError errorDetails = new ApiError(
        status,
        HttpStatus.NOT_FOUND.getReasonPhrase(), // "Not Found"
        ex.getMessage(), // The specific message from the exception
        request.getDescription(false).substring(4) // Extracts the request path, e.g., "/api/users/123"
    );

    // 3. Return the formatted response
    return new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND);
}
```

### Key Integration Points:

- **`@ExceptionHandler(ResourceNotFoundException.class)`**: This tells Spring to only execute this method when a `ResourceNotFoundException` is thrown.
    
- **`HttpStatus.NOT_FOUND` (404)**: The handler explicitly sets the correct HTTP status code for this specific exception type.
    
- **`ex.getMessage()`**: This retrieves the specific, detailed message (e.g., "User not found with ID 5") from the thrown exception, which populates the `message` field of the `ApiError` object.
    
- **`WebRequest request`**: This object provides access to the request context, allowing the handler to extract the **requested URI/path** (to populate the `path` field).
    
- **`new ResponseEntity<>(errorDetails, HttpStatus.NOT_FOUND)`**: The method returns a `ResponseEntity` containing the structured **`ApiError`** object in the body, ensuring the client receives the expected JSON format along with the correct **404** status code.
    

In essence, the Global Exception Handler acts as a **translator**, catching raw Java exceptions and translating them into the consistent, standardized, and client-friendly JSON format defined by your `ApiError` class.