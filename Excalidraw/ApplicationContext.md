The **ApplicationContext** is a foundational element in Spring Boot and the wider Spring Framework. It serves as the central container for your application's components.

## 🧠 Core Concept: IoC Container

The `ApplicationContext` interface represents the **Spring IoC (Inversion of Control) container**.

  * **Responsibility:** It is primarily responsible for **instantiating, configuring, and assembling** the application's components, which are known as **Spring Beans**.
  * **Metadata:** The container gets its instructions for managing these beans by reading **configuration metadata**, which in modern Spring Boot is typically provided via **Java annotations** (e.g., `@Configuration`, `@Component`, `@Service`, `@Repository`), but can also be XML or Java code.
  * **Life Cycle Management:** It manages the entire **lifecycle of beans**, including creation, dependency injection (wiring), and destruction.

-----

## ✨ Features and Functionality

The `ApplicationContext` is an advanced form of the basic `BeanFactory` and provides additional, enterprise-specific functionalities:

| Feature | Description |
| :--- | :--- |
| **Bean Factory Access** | Provides methods (like `getBean()`) for accessing application components (beans) by name or type. |
| **Dependency Injection (DI)** | Facilitates **autowiring**, where the container automatically injects required dependencies into beans, promoting loose coupling. |
| **Resource Loading** | Provides the ability to load file resources (e.g., configuration files, images) in a generic way, abstracting from the source (file system, classpath, URL). |
| **Internationalization (I18N)** | Supports **message resolution** (loading localized messages/text) to support different languages and locales. |
| **Event Publishing** | Enables the publishing of **application events** to registered listeners, allowing components to communicate asynchronously. |
| **Hierarchy** | Supports a **context hierarchy**, where multiple contexts can be nested (e.g., a root context for shared services and child contexts for web components). |

-----

## 🚀 ApplicationContext in Spring Boot

In a standard Spring Boot application, the `ApplicationContext` is automatically created and configured when the main class's `SpringApplication.run()` method is executed.

  * **Entry Point:** The static `run()` method returns an instance of the specific `ApplicationContext` implementation being used (commonly a `ConfigurableApplicationContext` implementation like `AnnotationConfigServletWebServerApplicationContext` for web apps).
    ```java
    public static void main(String[] args) {
        ApplicationContext context = SpringApplication.run(DemoApplication.class, args);
        // 'context' is the ApplicationContext instance
    }
    ```
  * **Auto-Configuration:** Spring Boot leverages the classpath and configured beans to perform **Auto-Configuration**. It dynamically wires up necessary beans and settings and applies them to the `ApplicationContext`, greatly simplifying setup (e.g., automatically configuring an embedded Tomcat server, a `DataSource`, etc.).
  * **Accessing the Context:** While the primary way to interact with beans is through **Dependency Injection** (using `@Autowired` or constructor injection), you can directly access the `ApplicationContext` if needed:
    1.  **Autowiring:** Inject the context into a component:
        ```java
        @Autowired
        private ApplicationContext context;
        ```
    2.  **`ApplicationContextAware`:** Implement the `ApplicationContextAware` interface, which provides a callback method (`setApplicationContext`) to receive a reference to the context.

The video below explains two ways to retrieve the ApplicationContext object in a Spring Boot application.

[using ApplicationContext in Spring Boot Application](https://www.youtube.com/watch?v=7oGPkjmF4y0)