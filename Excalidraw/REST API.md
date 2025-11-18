A **REST API (Representational State Transfer API)** is the most common and standardized way to build web APIs today.

If the general API is the waiter, the **REST API is the specific set of rules** the waiter and kitchen must follow to handle your order efficiently.

### **Key Concepts in Plain English:**

| Concept | Plain English Analogy | Technical Term |
| :--- | :--- | :--- |
| **Resources** | Everything you want to get or change is treated as an **object** (like a specific **dish** or a **table**). | **Resources** (e.g., `/users`, `/products/123`) |
| **Statelessness** | The waiter **forgets** everything about your previous orders between visits. Every new order (request) must contain *all* the information needed to fulfill it. | **Stateless** |
| **Standardized Actions** | There are only a few standard ways to interact with the objects (like "order it," "cancel it," "check what it is"). | **HTTP Methods** (GET, POST, PUT, DELETE) |

---

### **The Four Core Actions (HTTP Methods)**

These four standardized commands are what you use to interact with the server's data (the "resources"):

1.  **GET:** 📖
    * **Purpose:** **Retrieve** data from the server.
    * **Analogy:** You ask the waiter, "**What** dishes do you have?" (You get a list of products).
2.  **POST:** ✍️
    * **Purpose:** **Create** new data on the server.
    * **Analogy:** You tell the waiter, "**I want** to order a new steak." (You create a new user profile).
3.  **PUT/PATCH:** ✏️
    * **Purpose:** **Update** existing data on the server.
    * **Analogy:** You tell the waiter, "**Change** my steak order from medium to well-done." (You modify a user's email address).
    * *(Note: **PUT** typically replaces the whole resource; **PATCH** updates only a part.)*
4.  **DELETE:** 🗑️
    * **Purpose:** **Remove** data from the server.
    * **Analogy:** You tell the waiter, "**Cancel** that order." (You delete a post or a user account).

---

In short, a **REST API** uses simple web addresses (**URLs**) to identify the *thing* (resource) you want, and standard actions (**GET, POST, PUT, DELETE**) to specify *what* you want to do with it.