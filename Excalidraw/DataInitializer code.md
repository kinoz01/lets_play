## ⏳ Placement in the Startup Lifecycle

Your `DataInitializer` class implements `CommandLineRunner`, which means its `run()` method is specifically designed to execute **after** the entire Spring application context is fully loaded, but **before** the application is officially declared "ready."

| **Code Element**                         | **Lifecycle Step**                                       | **Explanation**                                                                                                                                                                                                                                           |
| ---------------------------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@Component`**                         | **Step 5: Perform Component Scanning**                   | Spring finds this class, identifies it as a configuration component, and creates a **Bean Definition** (a blueprint) for `DataInitializer`.                                                                                                               |
| **Constructor** (`DataInitializer(...)`) | **Step 8: Instantiate all singleton beans**              | The constructor is called here. Spring injects the required dependencies: `userRepository`, `passwordEncoder`, `adminEmail`, and `adminPassword`. This relies on the beans for `UserRepository` and `PasswordEncoder` already being created in this step. |
| **`@Override public void run(...)`**     | **Step 12: Run CommandLineRunner and ApplicationRunner** | This is the exact step where Spring executes the `run()` method of every bean that implements `CommandLineRunner`.                                                                                                                                        |

<hr>

## 💡 Detailed Execution of `run()`

The logic inside your `run()` method executes precisely at **Step 12**, right before the `ApplicationReadyEvent` (Step 13) is fired.

The steps inside the `run()` method rely entirely on the dependencies injected in Step 9:

1. **`userRepository.existsByEmail(adminEmail)`:** This call executes the logic within the **dynamically generated `UserRepository` proxy** (created in Step 8). This checks the MongoDB database to see if an admin user already exists.
    
2. **`passwordEncoder.encode(adminPassword)`:** Uses the injected `PasswordEncoder` bean to securely hash the admin password.
    
3. **`userRepository.save(admin)`:** If the user doesn't exist, the new `User` document is persisted to the MongoDB database using the generated repository proxy.
    

This is a common and correct pattern for **seeding initial data** (like an admin account) only once when an application starts.