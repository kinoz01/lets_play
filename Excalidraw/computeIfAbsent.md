Here's a quick breakdown of how the flow works:

1. **Input to `computeIfAbsent`:** You call the method:
    
    Java
    
    ```
    SimpleBucket bucket = cache.computeIfAbsent(ip, this::createBucket);
    ```
    
    The first argument, **`ip`** (the client's IP address), is the key you are trying to find in the `cache` map.
    
2. **Key is Absent:** If the `cache` **does not** contain an entry for that `ip`, `computeIfAbsent` knows it needs to compute a new value (the `SimpleBucket`).
    
3. **The Key is Passed:** To compute the value, `computeIfAbsent` executes the function you provided (`this::createBucket`) and **automatically passes the key (`ip`)** as an argument to that function.
    
4. **Key Becomes Argument:** Your `createBucket` method receives the key:
    
    Java
    
    ```
    private SimpleBucket createBucket(String key) { // The 'key' here is the IP address
        return new SimpleBucket(CAPACITY, REFILL_WINDOW_MS);
    }
    ```
    

So, the key (`ip`) is the value that triggers the call to `createBucket` and is simultaneously passed to it as its input argument.

---

The `::` operator is used to create a **Method Reference**. It's shorthand for a **Lambda Expression** that simply calls an existing method.

- **Syntax:** `ContainingClass::methodName` or `objectName::methodName`
    
- **Your Case:** `this::createBucket` refers to the `createBucket` method of the current object (`this`) of the `RateLimitingFilter` class.
    

### The Functional Equivalent (Lambda Expression)

In your code, the method reference is being passed as the second argument to the `computeIfAbsent` method of the `ConcurrentHashMap`:

Java

```
// Original code using Method Reference
cache.computeIfAbsent(ip, this::createBucket);

// The equivalent code using a full Lambda Expression
cache.computeIfAbsent(ip, (key) -> this.createBucket(key));
```

Both lines of code achieve the exact same result:

- The `computeIfAbsent` method requires a function (a **`Function`** functional interface) that takes a key (`String ip`) and returns a value (`SimpleBucket`).
    
- The method reference `this::createBucket` provides this function.