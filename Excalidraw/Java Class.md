### What a Class Defines

A class defines the structure and behavior that its objects will have. It acts as a logical container that specifies:

  * **Attributes (Fields or Member Variables):** These are the data or properties that an object of the class will hold. They define the **state** of the object.
      * *Example:* For a class called `Car`, the attributes might be `color`, `speed`, and `model`.
  * **Methods:** These are the actions or functions that an object of the class can perform. They define the **behavior** of the object.
      * *Example:* For the `Car` class, the methods might be `startEngine()`, `accelerate()`, and `brake()`.

-----

### Key Concepts

  * **Object:** An **instance** of a class. When you create an object, you are creating a concrete entity based on the class blueprint. You can create multiple, independent objects from a single class.
      * *Analogy:* The class `Car` is the blueprint, while your red sedan and your neighbor's blue SUV are **objects** (instances) of the `Car` class.
  * **Encapsulation:** Classes support encapsulation, which is the bundling of **data (attributes)** and the **methods** that operate on that data into a single unit (the class). This also allows for **data hiding**, controlling access to the internal state of the object.

-----

### Basic Java Class Structure

Here is a simplified example of how a class is declared in Java:

```java
public class Dog { // Class Declaration
    
    // Attributes (State/Data)
    String breed;
    String name;
    int age;
    
    // Methods (Behavior/Actions)
    public void bark() {
        System.out.println(name + " says Woof!");
    }
    
    public void run(int distance) {
        System.out.println(name + " ran " + distance + " meters.");
    }
}
```

You would then **instantiate** (create) objects from this class:

```java
Dog myDog = new Dog(); // Creating an object named myDog
myDog.name = "Max";    // Setting an attribute
myDog.bark();          // Calling a method
```