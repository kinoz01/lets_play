The truth is a combination of both: **Maven Core** resolves the dependencies, but **Plugins** typically construct and use the final classpath for specific tasks.

---

## 1. Maven Core: Dependency Resolution

**Maven itself** (the core engine) is responsible for reading your `pom.xml`, calculating the complete, conflict-resolved set of dependencies (including all transitives), and downloading them from repositories into your local `.m2` cache.

- **Role of Core:** To determine the full list of required JAR files and their locations on your disk based on dependency mediation rules (nearest wins, first declaration wins, etc.).
    
- **Output:** The core engine provides a collection of **Artifacts** to the build environment, categorized by scope (compile, test, runtime). This collection is the _potential_ classpath.
    

---

## 2. Plugins: Classpath Construction and Execution

While Maven Core resolves the list, a specific **plugin** is responsible for taking that list and constructing the actual classpath string (the sequence of file paths) used to execute a task.

The classpath varies depending on the lifecycle phase and the plugin being executed:

|**Lifecycle Phase**|**Plugin Involved**|**Classpath Constructed**|
|---|---|---|
|`compile`|**`maven-compiler-plugin`**|Uses dependencies with scopes **`compile`**, **`provided`**, and **`system`**.|
|`test`|**`maven-surefire-plugin`**|Uses dependencies with scopes **`compile`**, **`provided`**, **`system`**, and **`test`**, plus the project's compiled classes and test classes.|
|`package`|**`maven-jar-plugin`**|Often constructs the `Class-Path` entry inside the final JAR's manifest file, typically using **`runtime`** scoped dependencies.|

### The `maven-surefire-plugin` Example

The `maven-surefire-plugin` (which runs your unit tests) is a perfect example:

1. **Maven Core** provides the plugin with the list of all resolved dependencies.
    
2. The **Surefire Plugin** then takes that list, adds the project's output directories (`target/classes` and `target/test-classes`), filters the dependencies by scope (`test` scope for tests), and combines all these paths into the final classpath string passed to the JVM to execute the tests.1
    

In short, **Maven Core provides the ingredients, and the plugins assemble the final meal** (the classpath) for their specific execution environment.

---> [[Maven & Spring plugin relation]]
