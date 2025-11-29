Generics in Java are a powerful feature that allows you to write **classes, interfaces, and methods** that can operate on objects of **various types** while providing **compile-time type safety**.

In simple terms, think of generics as a way to create a blueprint that works with **types as placeholders**.

-----

## 🔑 Key Concepts of Generics

Here's a breakdown of the core ideas:

### 1\. Type Safety

Before generics, if you wanted to create a list that could hold any type of object, you'd use the non-generic `ArrayList`. However, you could accidentally add a `String` to a list intended for `Integer`s, and this mistake would only be caught when the program runs (a **runtime error**).

With generics, you specify the type when you create the object, like `ArrayList<String>`. The compiler then enforces this, preventing you from adding an `Integer` to this list. This moves potential errors from runtime to **compile time**, which is much safer and easier to fix.

### 2\. Eliminating Casts

Without generics, when you retrieve an object from a collection, it is treated as a generic `Object`, and you have to explicitly **cast** it back to its original type.

  * **Without Generics:**

    ```java
    Object obj = list.get(0);
    String s = (String) obj; // Required explicit cast
    ```

  * **With Generics:**

    ```java
    String s = list.get(0); // No cast needed
    ```

    The compiler knows `list.get(0)` returns a `String`.

### 3\. Type Parameters (The Placeholders)

Generics use **type parameters**, which are essentially variables for types. These are usually single uppercase letters, like `E` (for Element, used in Collections), `K` (for Key), `V` (for Value), or `T` (for Type).

When defining a generic class or method, you use these parameters in angle brackets (`<>`).

-----

## 💡 Examples

### 1\. Generic Class

Imagine you want a simple class that can hold one item, regardless of its type.

#### **Non-Generic (Bad)**

```java
class Box {
    private Object item;

    public void setItem(Object item) {
        this.item = item;
    }

    public Object getItem() {
        return item;
    }
}

// Usage: Prone to error
Box myBox = new Box();
myBox.setItem("Hello"); // Storing a String
// myBox.setItem(123); // Could accidentally store an Integer later!

String str = (String) myBox.getItem(); // Requires a cast
```

#### **Generic (Good)**

```java
class Box<T> { // <T> is the Type Parameter
    private T item; // T is used as the type of the item

    public void setItem(T item) {
        this.item = item;
    }

    public T getItem() {
        return item;
    }
}

// Usage: Safe and simple
Box<String> stringBox = new Box<String>();
stringBox.setItem("Hello Generics!"); // Compiler ensures only Strings are accepted

String str = stringBox.getItem(); // No cast is needed, return type is guaranteed String

// Box<Integer> integerBox = new Box<Integer>();
// integerBox.setItem("Wrong Type"); // Compile-time error!
```

### 2\. Generic Method

You can also make individual methods generic, even inside a non-generic class.

```java
public class ArrayUtils {
    // The <T> before the return type signals this is a generic method
    public static <T> void printArray(T[] array) { 
        for (T element : array) {
            System.out.println(element);
        }
    }
}

// Usage
Integer[] intArray = {1, 2, 3};
String[] stringArray = {"A", "B", "C"};

ArrayUtils.printArray(intArray);    // T is inferred as Integer
ArrayUtils.printArray(stringArray); // T is inferred as String
```

-----

## ⛓️ Bounded Type Parameters

Sometimes you want to restrict the types that can be used for a generic parameter. This is called a **bounded type parameter**.

You use the `extends` keyword to specify a bound. Note that `extends` is used even for interfaces.

  * **Example: Restricting to Numbers**

    If you want a method to calculate the sum of elements, the type parameter `T` must be some kind of `Number` (like `Integer`, `Double`, etc.).

    ```java
    // T must be a subclass of Number or Number itself
    public static <T extends Number> double getSum(T[] array) {
        double sum = 0;
        for (T element : array) {
            sum += element.doubleValue(); // We can safely call Number methods
        }
        return sum;
    }

    // Usage:
    Double[] values = {1.5, 2.5, 3.0};
    System.out.println(getSum(values)); // Works (T is Double, which extends Number)

    // String[] names = {"A", "B"};
    // getSum(names); // Compile-time error! String does not extend Number
    ```

-----

## 🚫 What Generics Cannot Do (Type Erasure)

Java generics are implemented using a technique called **Type Erasure**.

1.  **Generics only exist at compile-time.**
    During compilation, the compiler removes (erases) all the generic type information (the `<String>`, `<T>`, etc.) and replaces them with their bounds (or `Object` if no bound is specified).

2.  **No `new T()`**
    Because the runtime doesn't know what `T` is, you cannot create an instance of a generic type parameter directly inside a generic class: `T item = new T();` will not compile.

3.  **No primitive types**
    The type parameter *must* be an object type (a reference type). You cannot use primitive types like `int`, `char`, or `double`. You must use their wrapper classes (`Integer`, `Character`, `Double`).