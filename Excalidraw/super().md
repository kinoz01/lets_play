### What is `super` in Java?

In Java, classes can inherit from other classes (Parent $\rightarrow$ Child).

**`super` is a reference variable used by a Child class (Subclass) to refer to its immediate Parent class (Superclass).**

Think of `super` as a direct phone line to your parent. Whenever you (the Child class) need something that belongs to your Parent—a variable, a method, or their startup instructions—you pick up the phone and dial `super`.

You generally use it for three specific tasks:

1. **Calling the Parent's Constructor.**
    
2. **Accessing the Parent's Methods** (especially if you overrode them).
    
3. **Accessing the Parent's Variables** (if hidden by the child).
    

---

### 1. Calling the Parent's Constructor (`super()`)

This is the most common use. When you create a new Child object, you almost always need to run the setup code (constructor) of the Parent first.

**The Rule:** If you use `super()` to call a constructor, it **must** be the very first line inside the Child's constructor.

#### Analogy: The House Foundation

Imagine building a specific type of house, like a `Villa`. Before you can build the fancy `Villa` features (balconies, pool), you must build the generic `House` foundation (walls, roof).

- **Parent:** House (builds walls)
    
- **Child:** Villa (adds pool)
    

#### Example Code

```java
class House {
    House(String address) {
        System.out.println("🔨 Built the walls at " + address);
    }
}

class Villa extends House {
    Villa(String address, boolean hasPool) {
        // 1. Call the Parent (House) constructor FIRST
        super(address); 
        
        // 2. Do the Child (Villa) work
        if(hasPool) {
            System.out.println("🏊 Filled the swimming pool.");
        }
    }
}

public class Main {
    public static void main(String[] args) {
        Villa myHome = new Villa("123 Java Lane", true);
    }
}
```

**Output:**

```
🔨 Built the walls at 123 Java Lane
🏊 Filled the swimming pool.
```

Why is this important?

If you didn't call super(address), the House wouldn't know where to build the walls. The parent must be initialized before the child can add to it.

> **Note:** If you don't type `super()` yourself, Java actually adds a hidden, invisible `super()` (with no arguments) as the first line of your constructor automatically!

---

### 2. Accessing Parent Methods (`super.methodName`)

Sometimes, a Child class changes the behavior of a method it inherited (this is called **Overriding**). But what if you still want the original behavior involved?

You use `super.methodName()` to say: _"Run the original version of this function, then run my new version."_

#### Example: The Employee Paycheck

Imagine a generic `Employee` and a `Manager`.

- **Employee** gets a base salary.
    
- **Manager** gets the base salary **plus** a bonus.


```java
class Employee {
    void calculatePay() {
        System.out.println("Authorized base salary transfer: $5000");
    }
}

class Manager extends Employee {
    // Overriding the method
    @Override
    void calculatePay() {
        // 1. Do the normal Employee stuff first
        super.calculatePay(); 
        
        // 2. Add Manager specific stuff
        System.out.println("Authorized bonus transfer: $2000");
    }
}

public class Main {
    public static void main(String[] args) {
        Manager boss = new Manager();
        boss.calculatePay();
    }
}
```

**Output:**

```
Authorized base salary transfer: $5000
Authorized bonus transfer: $2000
```

Without `super.calculatePay()`, the Manager would _only_ get the bonus ($2000) and lose their base salary!

---

### 3. Accessing Parent Variables (`super.variableName`)

This is the least common usage. It happens when a Child class has a variable with the **exact same name** as the Parent class (this is called "shadowing").

To tell Java you want the Parent's version of the variable, not the Child's, you use `super`.

#### Example: Vehicle Speed


```java
class Vehicle {
    int maxSpeed = 120; // Parent variable
}

class SportsCar extends Vehicle {
    int maxSpeed = 300; // Child variable (same name!)

    void displaySpeed() {
        System.out.println("Sports Car Speed: " + maxSpeed); // Uses current class
        System.out.println("Generic Vehicle Speed: " + super.maxSpeed); // Uses parent
    }
}

public class Main {
    public static void main(String[] args) {
        SportsCar ferrari = new SportsCar();
        ferrari.displaySpeed();
    }
}
```

**Output:**

```
Sports Car Speed: 300
Generic Vehicle Speed: 120
```

---

### Summary Table

|**Syntax**|**Used In**|**Purpose**|
|---|---|---|
|`super()`|Constructor|Calls the Parent's default constructor. Must be the **first line**.|
|`super(args)`|Constructor|Calls the Parent's specific constructor with arguments. Must be the **first line**.|
|`super.method()`|Any Method|Calls a method from the Parent class (useful when you have overridden it).|
|`super.variable`|Any Method|Accesses a variable from the Parent class (useful if the Child has a variable with the same name).|

---> [[java default constructor]]
---> What if the class doesn't extend any class (doesn't have parent) will java create `super()` in this case or constructor? [[super() note]]