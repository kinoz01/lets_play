## How Maven Constructs a Classpath

The fundamental job of Maven is to translate the human-readable configuration in your `pom.xml` into the massive, explicit list of JAR files (`-classpath` string) that the Java compiler (`javac`) or the Java Virtual Machine (`java`) needs to execute its task.

---

### 1. 📖 Reading and Consolidating the POM Configuration

Maven starts by reading your project's **Project Object Model (POM)**, which is the `pom.xml` file. The final, effective configuration is a combination of several sources:

- **Explicit Dependencies:** The `<dependencies>` section in your immediate `pom.xml`.
    
- **Inherited Dependencies:** Any dependencies defined in the `<parent>` POMs your project inherits from.
    
- **Dependency Management:** The `<dependencyManagement>` section, which dictates the **version** and **scope** for dependencies, ensuring consistency across modules.
    
- **Active Profiles:** Configurations activated by specific runtime conditions or command-line flags. These can add or remove dependencies.
    

This step generates a comprehensive list of all _declared_ dependencies and their defined properties (groupId, artifactId, version, scope).

---

### 2. 🎯 Resolving and Filtering Dependencies by Scope

The **scope** of a dependency determines when and where it's needed—compile time, test time, or runtime. Maven filters the master list of dependencies based on the current **lifecycle phase** (goal) being executed:

|**Scope**|**Description**|**Included for mvn compile**|**Included for mvn test**|**Included for mvn package (in WAR/JAR)**|
|---|---|---|---|---|
|**`compile`**|Required for **all** stages.|Yes|Yes|Yes|
|**`provided`**|Required for compile/test, but **expected** to be provided by the runtime environment (e.g., a servlet container).|Yes|Yes|No|
|**`runtime`**|Not needed for compilation, only for execution.|No|Yes|Yes|
|**`test`**|Only needed for compiling and running test code.|No|Yes|No|
|**`system`**|Similar to `provided`, but points to a local, non-repository JAR file.|Yes|Yes|No|

**Example Filtering:**

- **`mvn compile`** only needs scopes: `compile` and `provided`.
    
- **`mvn test`** needs scopes: `compile`, `provided`, `runtime`, and `test`.
    

---

### 3. 🔗 Resolving Transitive Dependencies and Conflicts

This is the most complex step. Most of the JARs in your `classpath` come not from your direct declarations, but from your dependencies' own dependencies (**transitive dependencies**).

1. **Dependency Graph Creation:** For every direct dependency you've kept after scope filtering, Maven looks inside its `pom.xml` (which is downloaded and stored in the **local repository** at `~/.m2/repository`). It reads that dependency's dependencies, and then _their_ dependencies, recursively, building a large **dependency graph**.
    
2. **Conflict Resolution:** It's common for two different dependencies to rely on different versions of the _same_ third-party library (e.g., Spring Boot wants Jackson v2.15, but another library wants Jackson v2.13). Maven uses two main rules to resolve these conflicts:
    
    - **"Nearest Wins":** The version of a dependency closest to your project in the dependency tree is chosen. A direct dependency always wins over a transitive one.
        
    - **"First Declared Wins":** If two dependency paths are the same length (equidistant from your project), the one declared _first_ in the main `pom.xml` is chosen.
        

After this stage, Maven has a final, consolidated list of every single JAR (and its specific version) required for the current goal.

---

### 4. 📂 Mapping Dependencies to Local File Paths

Now that Maven knows **which** dependencies and **which versions** are needed, it translates each one into a precise physical path on your local machine.

Every dependency is mapped to a standard path in the local repository:

$$\text{Path} = \sim/.m2/\text{repository}/\text{groupId}/\text{artifactId}/\text{version}/\text{artifactId}-\text{version}.\text{jar}$$

- Example: A dependency with org.springframework.boot:spring-boot:3.3.2 will map to:
    
    ~/.m2/repository/org/springframework/boot/spring-boot/3.3.2/spring-boot-3.3.2.jar
    

---

### 5. ⚙️ Building the Classpath Command String

Finally, Maven gathers all the required paths and formats them into a single string for the Java command:

1. **Local Classes:** It adds your project's compiled output paths first: `target/classes` and/or `target/test-classes`.
    
2. **JAR Files:** It appends the absolute file path for every resolved JAR dependency (from step 4).
    
3. **Separator:** It uses the platform-specific separator: **`:`** on Linux/macOS or **`;`** on Windows.
    

**The final classpath string looks like this:**

```
-classpath target/classes:target/test-classes:/path/to/.m2/spring-boot-3.3.2.jar:/path/to/.m2/spring-core-6.0.9.jar:...
```

This string is then passed as the `-classpath` (or `-cp`) argument when Maven executes commands like `javac` (compiler) or `java` (runtime/tests/plugins).

- You can inspect this final list yourself using the goal: `mvn dependency:build-classpath`.