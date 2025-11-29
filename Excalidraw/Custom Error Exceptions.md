These are custom exceptions designed to signal **business logic failures** that occur _deep inside_ your application (usually the Service Layer) back to the presentation layer (the Controller/Global Handler).

|**Your Custom Exception**|**What it Means (Service Layer)**|**Status Implied**|
|---|---|---|
|**`ResourceNotFoundException`**|"Database lookup failed for a user/product."|404 Not Found|
|**`BadRequestException`**|"A business rule was violated (e.g., duplicate email during registration)."|400 Bad Request|
|**`UnauthorizedException`**|"Credentials failed during manual check (rarely used)."|401 Unauthorized|
|**`ForbiddenException`**|"User has authentication but lacks the necessary role to proceed."|403 Forbidden|

---

## 2. 🎣 How the Handler Catches Your Custom Exceptions

The `GlobalExceptionHandler` catches your custom exceptions **directly by their specific class types** using the `@ExceptionHandler` annotation.

You provided the logic to handle these specific types:

|**Custom Exception Class**|**Matching Handler in GlobalExceptionHandler**|
|---|---|
|`ResourceNotFoundException`|`@ExceptionHandler(ResourceNotFoundException.class)`|
|`ForbiddenException`|`@ExceptionHandler(ForbiddenException.class)`|
|`UnauthorizedException`|`@ExceptionHandler(UnauthorizedException.class)`|
|`BadRequestException`|`@ExceptionHandler({ BadRequestException.class, ... })`|

### Key Point on `RuntimeException`

The fact that they extend **`RuntimeException`** simply means they are **[[unchecked exception]]** (you don't have to declare them in method signatures), allowing them to bubble up the call stack automatically until the global handler catches their specific type.