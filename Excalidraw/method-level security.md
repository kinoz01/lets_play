Method-level security is a mechanism used in software development, particularly in Java-based applications using frameworks like **Spring Security**, to **control access** to individual **methods** within a class based on the caller's identity, roles, and/or permissions.

It provides a fine-grained level of authorization, in contrast to **URL-level security**, which secures entire endpoints or resources.

---

## 🔑 Core Concepts

Method-level security relies on several key elements:

- **Annotations:** It is primarily configured using **annotations** placed directly on the method definition. These annotations instruct the security framework on the required authorization rules.
    
- **Authorization Manager:** The security framework utilizes an **Authorization Manager** or **Access Decision Manager** to evaluate the security expressions defined in the annotations against the authenticated user's details.
    
- **Method Interception:** When a protected method is called, the security mechanism **intercepts** the call **before** the method's logic executes. If the authorization check fails, the method is **not executed**, and an exception (typically `AccessDeniedException`) is thrown.
    

---

## 🛡️ Common Annotations (Spring Security Example)

The following are the most common annotations used for method-level security in Spring Security:

|**Annotation**|**Purpose**|**Example**|
|---|---|---|
|**`@Secured`**|Restricts access based on a **list of roles**. Requires the user to have at least one of the specified roles.|`@Secured("ROLE_ADMIN")`|
|**`@RolesAllowed`**|Part of the JSR-250 standard, similar to `@Secured` for role-based access.|`@RolesAllowed({"USER", "ADMIN"})`|
|**`@PreAuthorize`**|Executes a **Spring Expression Language (SpEL)** expression **before** the method is executed. This is the most flexible option.|`@PreAuthorize("hasRole('ADMIN') and #userId == authentication.principal.id")`|
|**`@PostAuthorize`**|Executes a **SpEL expression** **after** the method is executed, but **before** the result is returned. Useful for checking the result object itself.|`@PostAuthorize("returnObject.owner == authentication.name")`|
|**`@PreFilter`**|Applies authorization logic to **filter** the **input arguments** (e.g., collections) of the method before execution.|`@PreFilter("filterObject.isValid()")`|
|**`@PostFilter`**|Applies authorization logic to **filter** the **returned collection** of the method before it's given to the caller.|`@PostFilter("filterObject.active == true")`|

---

## 📝 Key Advantages of Using Method-Level Security

1. **Fine-Grained Control:** You can secure operations within the same class or endpoint differently. For example, a `GET /users/{id}` request might hit a `getUserById(id)` method. You can use `@PreAuthorize` to ensure a user can only fetch their **own** profile (`#id == authentication.principal.id`) unless they have the `ADMIN` role.
    
2. **Clearer Separation of Concerns:** The security configuration is placed directly with the business logic it protects, making the security requirements for that specific operation immediately clear to anyone reading the code.
    
3. **Contextual Security:** With `@PreAuthorize` and [[Spring Expression Language (SpEL)|SpEL]], you can leverage method **arguments** (e.g., the ID of the resource being accessed) and the method's **return value** for authorization decisions, enabling sophisticated security rules.
    

---

## ⚙️ Implementation Steps (General)

1. **Enable Method Security:** The first step is to enable method security in the application's configuration. In Spring, this often involves adding the `@EnableMethodSecurity` (or `@EnableGlobalMethodSecurity` in older versions) annotation to a configuration class.
    
2. **Define Security Expression:** Apply the appropriate security annotation (`@PreAuthorize`, `@Secured`, etc.) to the method you want to protect, defining the required role or security expression.
    
3. **Execute:** When the application runs and a protected method is called, the security layer intercepts the call and enforces the rule before allowing the method to proceed.