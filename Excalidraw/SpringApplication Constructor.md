First, example of the constructor as-is:

```java
public SpringApplication(ResourceLoader resourceLoader, Class<?>... primarySources) {
    this.addCommandLineProperties = true;
    this.addConversionService = true;
    this.headless = true;
    this.additionalProfiles = Collections.emptySet();
    this.applicationContextFactory = ApplicationContextFactory.DEFAULT;
    this.applicationStartup = ApplicationStartup.DEFAULT;
    this.properties = new ApplicationProperties();
    this.resourceLoader = resourceLoader;
    Assert.notNull(primarySources, "'primarySources' must not be null");
    this.primarySources = new LinkedHashSet(Arrays.asList(primarySources));
    this.properties.setWebApplicationType(WebApplicationType.deduceFromClasspath());
    this.bootstrapRegistryInitializers =
        new ArrayList(this.getSpringFactoriesInstances(BootstrapRegistryInitializer.class));
    this.setInitializers(this.getSpringFactoriesInstances(ApplicationContextInitializer.class));
    this.setListeners(this.getSpringFactoriesInstances(ApplicationListener.class));
    this.mainApplicationClass = this.deduceMainApplicationClass();
}
```

Now let’s go through it in detail, with small code blocks and explanation.

1.  Enable command-line properties
    

```java
this.addCommandLineProperties = true;
```

Meaning in plain English:

-   Spring Boot will read arguments like `--server.port=8085` from `args` passed to `main`.
    
-   Those become part of the Environment as properties.
    
-   Example: `--app.admin.email=foo@bar.com` becomes property `app.admin.email` that you can inject with `@Value` or `@ConfigurationProperties`.
    

2.  Enable the ConversionService
    

```java
this.addConversionService = true;
```

Meaning:

-   When Spring binds properties to fields or constructor params, it often needs to convert strings to other types.
    
-   With this flag on, Spring registers a default `ConversionService`.
    
-   So `"10"` → `Integer`, `"true"` → `Boolean`, `"2024-01-01"` → `LocalDate`, etc.
    

3.  Set the application as headless
    

```java
this.headless = true;
```

Meaning:

-   Tells the Java runtime: this app does not use AWT or Swing GUI stuff (no monitor, keyboard, mouse needed).
    
-   Most server apps and Spring Boot apps are “headless”.
    
-   This affects `java.awt.GraphicsEnvironment` and some desktop APIs.
    

4.  Initialize additional profiles as empty
    

```java
this.additionalProfiles = Collections.emptySet();
```

Meaning:

-   “Profiles” are Spring’s way of switching between configurations (dev, test, prod).
    
-   Here, the constructor starts with no extra profiles enabled.
    
-   Later you can add them via `spring.profiles.active`, env vars, or programmatically.
    

5.  Set default ApplicationContext factory
    

```java
this.applicationContextFactory = ApplicationContextFactory.DEFAULT;
```

Meaning:

-   This is a strategy for creating the correct type of `ApplicationContext` later.
    
-   It does not create anything now.
    
-   Later, based on the web type (Servlet, Reactive, None), this factory will build:
    
    -   `AnnotationConfigApplicationContext` (non-web)
        
    -   `ServletWebServerApplicationContext` (MVC)
        
    -   `ReactiveWebServerApplicationContext` (WebFlux)
        

6.  Set default ApplicationStartup
    

```java
this.applicationStartup = ApplicationStartup.DEFAULT;
```

Meaning:

-   Controls how Spring collects startup metrics / tracing.
    
-   Default is minimal and cheap.
    
-   Can be replaced by `BufferingApplicationStartup` or `FlightRecorderApplicationStartup` if you want detailed timing.
    

7.  Create internal ApplicationProperties
    

```java
this.properties = new ApplicationProperties();
```

Meaning:

-   This object stores internal settings for the SpringApplication.
    
-   It will hold things like:
    
    -   web application type
        
    -   lazy initialization flag
        
    -   shutdown behavior
        
    -   maybe some other boot-level flags.
        
-   Right after creation, they start filling it.
    

8.  Store the resource loader
    

```java
this.resourceLoader = resourceLoader;
```

Meaning:

-   If you pass a custom `ResourceLoader` when constructing SpringApplication, it is stored here.
    
-   Often null if you use the static `run(...)` method; then Spring uses a default loader.
    
-   A `ResourceLoader` knows how to load `classpath:`, `file:`, `http:` resources, etc.
    

9.  Validate that primarySources is not null
    

```java
Assert.notNull(primarySources, "'primarySources' must not be null");
```

Meaning:

-   `primarySources` are the classes you pass into `SpringApplication.run(...)`, usually your main app class:
    
    ```java
    SpringApplication.run(LetsPlayApplication.class, args);
    ```
    
-   Spring must have at least one class to bootstrap from, so it throws if null.
    

10.  Store the primary sources in a LinkedHashSet
    

```java
this.primarySources = new LinkedHashSet(Arrays.asList(primarySources));
```

Meaning:

-   Saves your main class(es) as a set while preserving insertion order.
    
-   This set usually contains just:
    
    ```java
    { LetsPlayApplication.class }
    ```
    
-   Spring will later:
    
    -   Use these as configuration classes
        
    -   Use their packages as base-package(s) for component scanning
        
    -   Use them to discover annotations like `@SpringBootApplication`
        

11.  Decide what kind of app this is (Servlet / Reactive / Non-web)
    

```java
this.properties.setWebApplicationType(WebApplicationType.deduceFromClasspath());
```

Meaning:

-   This is where Spring Boot detects what type of application you’re building.
    
-   `WebApplicationType.deduceFromClasspath()` checks the classpath:
    
    Roughly:
    
    -   If [[classpath]] contains Servlet APIs (like `javax.servlet.Servlet` or `jakarta.servlet.Servlet`) and Spring MVC → `SERVLET`
        
    -   Else if it finds WebFlux classes → `REACTIVE`
        
    -   Else → `NONE` (non-web app, like a CLI tool)
        
-   The result (enum `WebApplicationType`) is stored inside `properties`.
    
-   *This does not start a server yet*. It only sets a flag like “I am a Servlet app”.
    

12.  Load BootstrapRegistryInitializers from spring.factories
    

```java
this.bootstrapRegistryInitializers =
    new ArrayList(this.getSpringFactoriesInstances(BootstrapRegistryInitializer.class));
```

Meaning:

-   `getSpringFactoriesInstances(...)` scans `META-INF/spring.factories` (or newer configuration mechanisms) on the classpath.
    
-   It looks for classes that implement `BootstrapRegistryInitializer`.
    
-   These are used mainly by advanced stuff (Spring Cloud, etc.) to register things very early in the bootstrap process.
    
-   The constructor collects them into a list.
    

13.  Load ApplicationContextInitializers
    

```java
this.setInitializers(this.getSpringFactoriesInstances(ApplicationContextInitializer.class));
```

Meaning:

-   Similar mechanism: scan for implementations of `ApplicationContextInitializer`.
    
-   These are callbacks that run just before the `ApplicationContext` is refreshed.
    
-   Libraries use them to customize the context before beans are created.
    
-   `setInitializers(...)` stores them inside the SpringApplication instance.
    

14.  Load ApplicationListeners
    

```java
this.setListeners(this.getSpringFactoriesInstances(ApplicationListener.class));
```

Meaning:

-   Again, scan for `ApplicationListener` implementations using `spring.factories`.
    
-   These listeners will receive application events like:
    
    -   ApplicationStartingEvent
        
    -   ApplicationPreparedEvent
        
    -   ApplicationReadyEvent
        
    -   ApplicationFailedEvent
        
-   `setListeners(...)` attaches them to the SpringApplication so they are active during startup and runtime.
    

15.  Guess the main application class
    

```java
this.mainApplicationClass = this.deduceMainApplicationClass();
```

Meaning:

-   Spring tries to figure out which class contains the `public static void main(String[] args)` method that launched the app.
    
-   It does this by inspecting the current stack trace.
    
-   Used mainly for:
    
    -   Logging the app name in logs
        
    -   Better error messages
        

Putting it all together in one paragraph

This constructor prepares a SpringApplication object by:

-   Enabling command-line property binding and type conversion,
    
-   Marking the app as headless,
    
-   Initializing default settings and factories (ApplicationContextFactory, ApplicationStartup, ApplicationProperties),
    
-   Remembering your main application class and primary sources,
    
-   Detecting what kind of app you have (Servlet, Reactive, or non-web) based on the classpath,
    
-   Loading early bootstrap hooks (BootstrapRegistryInitializers),
    
-   Loading context initializers and application listeners from the classpath,
    
-   And guessing which class is your main entry point.
    

Important: at this stage, no beans are created, no context exists yet, and no server is started. That all happens later when `run(...)` is called on this prepared SpringApplication instance.