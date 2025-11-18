Understanding the difference between `extends` and `implements` is **fundamental to object-oriented programming (OOP)**, especially in languages like **Java** and **C#**.

Simply put:

* **`extends` is for Inheritance.** It's about becoming an improved version of one parent.
* **`implements` is for Contract Fulfillment.** It's about promising to perform specific actions defined by an interface.

---

## 🏗️ The `extends` Keyword (Inheritance)

The `extends` keyword is used to establish an **inheritance** relationship between two **classes**.

### What it Does
When Class B `extends` Class A:

1.  **Inheritance:** Class B (the **subclass** or **child**) automatically gets all the non-private **fields** (variables) and **methods** (functions) from Class A (the **superclass** or **parent**).
2.  **Specialization:** Class B can then add its own new fields and methods, or **override** (change the behavior of) the methods it inherited from Class A.
3.  **"Is-A" Relationship:** This establishes an **"is-a" relationship**. For example, a `Car` *extends* `Vehicle`, because a Car **IS A** type of Vehicle.

### Key Details
* **Source:** Used with **classes**.
* **Limit:** A class can only `extend` **one** other class (this is called **single inheritance**).
* **Purpose:** To reuse code and create a hierarchy of types where subclasses are specialized versions of their parents.

> **Example Analogy:** Think of Class A as a generic **Smartphone** and Class B as an **iPhone**. The iPhone `extends` Smartphone. It inherits the basic functions (call, text, screen) but adds its own specialized features (Siri, Face ID, etc.).

---

## 📜 The `implements` Keyword (Interface Contract)

The `implements` keyword is used to establish a contract relationship between a **class** and one or more **interfaces**.

### What it Does
An **Interface** is a blueprint (like a contract) that contains a set of abstract methods (methods without bodies).

When Class C `implements` Interface I:

1.  **Contract:** Class C is **required** to provide a complete, public implementation (method body) for **every single method** declared in Interface I.
2.  **Behavior Guarantee:** It guarantees that any object of Class C can perform the actions defined in Interface I.
3.  **"Can-Do" Relationship:** This establishes a **"can-do" relationship**. For example, a `JetPlane` *implements* `Flyable`, meaning the JetPlane **CAN DO** the action of flying.

### Key Details
* **Source:** Used with **interfaces**.
* **Limit:** A class can `implement` **multiple** interfaces (**multiple inheritance of behavior**).
* **Purpose:** To define a common behavior (a contract) that unrelated classes can agree to follow. It separates *what* an object should do from *how* it does it.

> **Example Analogy:** Think of Interface I as a **`Printable`** contract with a single method: `printDocument()`. A **LaserPrinter** `implements` Printable, and a **3DPrinter** also `implements` Printable. Both can fulfill the contract, but the *way* the LaserPrinter and the 3DPrinter fulfill the `printDocument()` method is completely different.

---

## 🆚 The Difference

The core difference lies in their purpose and what they allow the class to inherit:

| Feature | `extends` (Inheritance) | `implements` (Contract) |
| :--- | :--- | :--- |
| **Source Type** | A **Class** | An **Interface** |
| **Relationship** | **"Is-A"** (Inheritance of *code* and *type*) | **"Can-Do"** (Inheritance of *behavior contract*) |
| **Implementation** | Inherits **full implementation** (code) from the parent class. | **Must provide** a new, full implementation (code) for all methods. |
| **Quantity** | **Single inheritance:** A class can only `extend` **one** class. | **Multiple implementation:** A class can `implement` **many** interfaces. |
| **Primary Goal** | **Code Reuse** and creating type hierarchies. | **Defining Behavior** and establishing public contracts. |

---

### Can Classes be Called Interchangeably? (The Concept of Polymorphism)

The answer is **yes, in both cases**, due to a core concept in Object-Oriented Programming (OOP) called **polymorphism** (meaning "many forms").

1.  **When using `extends` (Inheritance):**
    * **Yes.** You can treat an object of the **subclass** (child) as an object of its **superclass** (parent).
    * **Why?** Because of the **"is-a"** relationship. A `Car` **is a** `Vehicle`. When a function is expecting a general `Vehicle`, passing a more specific `Car` works perfectly.

2.  **When using `implements` (Interface Contract):**
    * **Yes.** You can treat an object of the **implementing class** as an object of the **interface**.
    * **Why?** Because of the **"can-do"** relationship and the contract guarantee. If a function is expecting an object that can fulfill the `Flyable` interface contract, you can pass it a `JetPlane` or a `HotAirBalloon`. As long as they both *implement* `Flyable`, they are interchangeable from the perspective of that interface.

In both scenarios, you can use the more specific class interchangeably with its more general type (the superclass or the interface) because it is guaranteed to have the necessary properties or methods.

---