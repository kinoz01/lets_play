## Thread-Per-Request: The Default Model

The statement that "every incoming HTTP request is handled by a separate thread" is **absolutely true** for a standard, default Spring Boot setup.

1. **Thread Pool:** The embedded server (like Tomcat) maintains a **fixed thread pool**.1
    
2. **Request Assignment:** When an HTTP request comes in, a **dedicated thread** is immediately pulled from this pool and assigned to the request.
    
3. **Thread Life:** This thread is responsible for handling _everything_ for that request—from running your filters and controllers to fetching data from a database and finally sending the response back.
    
4. **Concurrency:** Since many requests arrive simultaneously, many threads are running **concurrently** (side-by-side) to handle them. This is why the `ConcurrentHashMap` was necessary in the rate-limiting example—to protect the shared data from simultaneous access by these multiple, concurrent threads.
    

---

## 🛑 The Blocking I/O Dilemma

This model **is** dealing with blocking I/O, and that is precisely its **weakness** when it comes to resource usage:

|**Concept**|**Explanation**|**The Problem**|
|---|---|---|
|**Blocking I/O**|When your dedicated request thread needs to perform an I/O operation (like querying MongoDB, calling a slow external API, or reading a file), the thread **stops and waits** (blocks) for the I/O to complete.|While the thread is blocked waiting for the database to respond, it is **wasting resources**. It is holding onto a valuable thread from the thread pool without doing any actual computation.|
|**Concurrency Limit**|The number of simultaneous requests your application can handle is limited by the size of the thread pool (e.g., 200 threads).|If 200 requests all hit a slow database query, all 200 threads become blocked, the thread pool is exhausted, and the application cannot accept **any new requests** until one of those 200 threads finishes its work.|

The thread-per-request model _enables_ concurrency (many threads running) but _suffers_ from **I/O blocking**, which severely limits scalability under heavy load involving slow dependencies.