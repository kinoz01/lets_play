This is a detailed explanation of a **Spring Boot REST Controller** named `UserController`, which manages CRUD (Create, Read, Update, Delete) operations for the **User** resource. This controller demonstrates strict security constraints, often limiting most operations to an `ADMIN` role.

---

## 🛠️ Controller Setup and Dependencies

- **`@RestController`**: Marks this class as a Spring component that handles incoming web requests and returns data (usually JSON) directly as the response body.
    
- **`@RequestMapping("/api/users")`**: Sets the **base URL path** for all methods in this controller to `/api/users`.
    
- **`private final UserService userService;`**: Declares a dependency on the **`UserService`**. The Controller handles the HTTP request/response flow, while the Service handles the core business logic (saving, fetching, validating data).
    
- **Constructor Injection**:

    ```java
    public UserController(UserService userService) {
        this.userService = userService;
    }
    ```
    
    Spring automatically injects a ready-to-use instance of the `UserService` into the controller when it's created, a best practice known as Dependency Injection.
    

---

## 🔒 Security and Access Control

This controller relies heavily on **Spring Security** annotations to control who can perform which action.

### 1. Getting All Users

- **`@GetMapping`**: Handles **GET** requests to `/api/users`.
    
- **`@PreAuthorize("hasRole('ADMIN')")`**: **Only users with the `ADMIN` role** can access this endpoint. This prevents regular users from fetching a list of all accounts.
    
- The method returns a list of `UserResponse` objects with a **200 OK** status by calling `userService.getAllUsers()`.
    

### 2. Getting a User by ID

- **`@GetMapping("/{id}")`**: Handles **GET** requests to `/api/users/{id}`.
    
- **`@PreAuthorize("hasRole('ADMIN') or (isAuthenticated() and #id == principal.id)")`**: This is a complex but crucial security expression:
    
    - An **`ADMIN`** user can view **any** user's details. **OR**
        
    - The user must be **`isAuthenticated()`** (logged in) **AND** the path variable **`#id`** (the ID being requested) must be equal to the ID of the currently logged-in user, represented by **`principal.id`**.
        
    - This implements a "self-access" rule, allowing users to see their own profile but not others'.
        
- It delegates to `userService.getUserById(id)`.
    

---

## 📝 Write Operations (CUD)

### 3. Creating a User

- **`@PostMapping`**: Handles **POST** requests to `/api/users` (used for resource creation).
    
- **`@PreAuthorize("hasRole('ADMIN')")`**: **Only users with the `ADMIN` role** can create new users through this specific API endpoint. Note: The public registration process is usually handled by a separate endpoint (e.g., `/auth/register`) with `@PermitAll`.
    
- **`@Valid @RequestBody UserRequest request`**: The request body is deserialized into a `UserRequest` object and is **validated** based on annotations defined in the `UserRequest` class (e.g., ensuring passwords meet complexity requirements).
    
- It calls `userService.createUser(request)` and returns the created user data with **200 OK**.
    

### 4. Updating a User (Full Replacement)

- **`@PutMapping("/{id}")`**: Handles **PUT** requests to `/api/users/{id}` (used for full resource replacement).
    
- **`@PreAuthorize("hasRole('ADMIN')")`**: **Only the `ADMIN` role** is allowed to update user accounts.
    
- **`@AuthenticationPrincipal User currentUser`**: The details of the currently logged-in user are automatically injected, allowing the service layer to implement logic, such as ensuring an admin cannot update another admin's security roles without proper checks.
    
- It delegates to `userService.updateUser(id, request, currentUser)`.
    

### 5. Partially Updating a User (Partial Modification)

- **`@PatchMapping("/{id}")`**: Handles **PATCH** requests to `/api/users/{id}` (used for partial resource modification).
    
- **`@PreAuthorize("hasRole('ADMIN')")`**: **Only the `ADMIN` role** is allowed.
    
- This method reuses the `userService.updateUser` method, assuming the service layer handles the partial update logic (e.g., only updating non-null fields in the request object).
    

### 6. Deleting a User

- **`@DeleteMapping("/{id}")`**: Handles **DELETE** requests to `/api/users/{id}`.
    
- **`@PreAuthorize("hasRole('ADMIN')")`**: **Only the `ADMIN` role** is allowed to delete user accounts.
    
- It calls `userService.deleteUser(id)` to perform the deletion.
    
- **`return ResponseEntity.noContent().build()`**: Returns a **204 No Content** HTTP status, which is the standard response for a successful deletion operation.