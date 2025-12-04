
The general principle is the same, but the **Spring Boot Maven Plugin** takes on an extra, specialized role when dealing with the classpath: **creating an executable fat JAR** and **managing the runtime environment**.

The process still follows the two-step model:

1. **Maven Core** resolves and mediates the standard project dependencies.
    
2. The **Spring Boot Maven Plugin** uses that resolved list to construct the classpath for its specific goals: `spring-boot:run` and `spring-boot:repackage`.
    

---

## 🚀 Spring Boot Plugin's Classpath Roles

The `spring-boot-maven-plugin` handles two distinct classpath scenarios:

### 1. For Development (`spring-boot:run`)

When you run `mvn spring-boot:run`, the plugin constructs the classpath for the embedded server process.

- It gathers all **`compile`** and **`runtime`** dependencies resolved by Maven Core.
    
- It explicitly includes the project's compiled classes and **`src/main/resources`** directory directly on the classpath.
    
    - **Reason:** This is done to enable "hot refreshing" of resources (like HTML, CSS, or properties files) during development, allowing you to see changes without a full rebuild.2
        
- It executes the application by spawning a JVM process and passing it the constructed classpath string, pointing to your application's **main class**.
    

### 2. For Packaging (Executable JARs)

This is where the Spring Boot Plugin fundamentally changes the structure compared to a standard Maven build. The plugin's **`repackage`** goal creates a "fat JAR" (or "uber-jar")

|**Feature**|**Standard Maven JAR**|**Spring Boot Executable JAR**|
|---|---|---|
|**Dependencies**|None (must be provided externally)|**Embedded** inside the JAR (`BOOT-INF/lib`)|
|**Main Class**|Your application's main class|`org.springframework.boot.loader.JarLauncher`|
|**Classpath**|Stored in the JAR's `MANIFEST.MF`|**Managed internally** by a custom classloader|

The plugin alters the classpath mechanism:

1. It bundles all dependencies into the final JAR, usually under a directory like `BOOT-INF/lib`.
    
2. It rewrites the JAR's `MANIFEST.MF` to point the `Main-Class` to the **Spring Boot Loader** (`JarLauncher`).
    
3. When you run `java -jar your-app.jar`, the **Spring Boot Loader** uses a **custom classloader** to find and load classes from the nested JARs inside `BOOT-INF/lib`, effectively creating the runtime classpath from within the single file.
    

So, while the plugin still _constructs_ the classpath (like other plugins), it does so in a special way to create a self-contained, executable application.