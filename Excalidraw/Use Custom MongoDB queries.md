While **Spring Data JPA** offers powerful query methods based on naming conventions, it also provides several ways to write your own custom queries when the convention isn't flexible enough or when you need more optimized, complex operations.

In your case, since you are using **Spring Data MongoDB**, you have two primary methods for writing custom queries beyond the generated `findByEmail` and `existsByEmail`:

---

## 1. ✍️ Using the `@Query` Annotation

The most common and straightforward way to define a custom query in Spring Data MongoDB is by using the **`@Query`** annotation directly above your repository method.

This annotation allows you to write the query using **MongoDB's JSON-based query language (the MongoDB Query Language or MQL)**.

### Example for Finding Users by Name (Custom Pattern Matching)

Suppose you want to find all users whose name starts with a specific string, ignoring case. You can use a regular expression in the MongoDB query:

```java
public interface UserRepository extends MongoRepository<User, String> {

    @Query("{ 'name' : { $regex: ?0, $options: 'i' } }") // The query is written in MQL
    List<User> findUsersByNameStartingWithIgnoreCase(String namePrefix);
    
    // ?0 refers to the first method parameter (namePrefix)
    // $regex is the MongoDB operator for regular expressions
    // $options: 'i' makes the match case-insensitive

    // Example Usage: findUsersByNameStartingWithIgnoreCase("jo") 
    // would find "John" and "joanne"
}
```

### Example for Complex Filtering (Multiple Criteria)

You can write queries that filter on multiple criteria:

```java
public interface UserRepository extends MongoRepository<User, String> {
    
    @Query("{ 'email' : ?0, 'role' : ?1 }")
    Optional<User> findByEmailAndRole(String email, Role role);

    // ?0 maps to 'email'
    // ?1 maps to 'role'
}
```

---

## 2. ⚙️ Using Custom Repository Implementations

For very complex operations that go beyond simple queries (e.g., performing multiple update operations, aggregation pipelines, or logic that requires the `MongoTemplate` API), you should create a **Custom Repository Implementation**.

This method involves creating a separate class that implements a custom interface, allowing you to manually inject and use the low-level **`MongoTemplate`**.

### Step 1: Define a Custom Interface

You first create an interface for your custom methods:

```java
public interface UserRepositoryCustom {
    List<User> findActiveUsersWithComplexQuery(Instant lastLogin);
}
```

### Step 2: Implement the Custom Interface

You create a class that implements this interface. Spring automatically names it by appending **`Impl`** to the repository name (`UserRepositoryImpl`):


```java
@Repository
public class UserRepositoryImpl implements UserRepositoryCustom {

    @Autowired
    private MongoTemplate mongoTemplate; // Inject the low-level template

    @Override
    public List<User> findActiveUsersWithComplexQuery(Instant lastLogin) {
        
        // Use the low-level MongoTemplate for complex operations
        Query query = new Query();
        query.addCriteria(Criteria.where("updated_at").gt(lastLogin));
        query.addCriteria(Criteria.where("role").is(Role.ADMIN));
        
        // This is where you can build aggregation pipelines or custom updates
        return mongoTemplate.find(query, User.class);
    }
}
```

### Step 3: Extend the Custom Interface

Finally, your main `UserRepository` interface extends both the Spring Data base interface and your custom interface:


```java
public interface UserRepository extends MongoRepository<User, String>, UserRepositoryCustom {
    // ... all other methods
}
```

By using **`@Query`** for simple MQL and **Custom Implementations** for complex operations, you maintain the clean structure of Spring Data while retaining the flexibility to perform any database operation you need.