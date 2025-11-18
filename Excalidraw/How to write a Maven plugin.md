## 🛠️ How to Write Your Own Maven Plugin

Creating a **Maven plugin** allows you to customize and extend the standard Maven build process with your own logic. Essentially, a plugin is a specialized **Java project** that houses one or more *goals*, which Maven calls **Mojos** (Maven POJO).

Here is a step-by-step, detailed explanation of how to write and use your own Maven plugin.

-----

### 1\. 🏗️ Set Up the Plugin Project

The first step is to create a standard Java project, but with a specific configuration that tells Maven it's a plugin.

#### **Create the `pom.xml` (Project Configuration)**

You define the project as a plugin by setting the `<packaging>` element to `maven-plugin`. This is the fundamental difference between a regular Java project and a plugin project.

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>my-maven-plugin</artifactId>
  <version>1.0.0</version>
  <packaging>maven-plugin</packaging>
  <name>My Maven Plugin</name>

  <dependencies>
    </dependencies>
</project>
```

-----

### 2\. 📝 Write the Mojo (The Goal) Class

A **Mojo** (Maven POJO) is the core of your plugin. It's a single Java class that contains the specific task you want Maven to perform.

#### **Mojo Class Requirements**

1.  **Extend `AbstractMojo`:** Your class must inherit from `org.apache.maven.plugin.AbstractMojo`. This provides access to Maven's logging and context.
2.  **Implement `execute()`:** This is the method where you write the actual logic of your plugin. It gets called when the goal is executed.
3.  **Annotate with `@Mojo`:** This annotation tells Maven the name of the goal that will invoke this class.

#### **Example Mojo Implementation (`SayHelloMojo.java`)**

```java
package com.example;

import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

// @Mojo(name = "say-hello") registers this class to be run when the goal "say-hello" is called.
@Mojo(name = "say-hello")
public class SayHelloMojo extends AbstractMojo {

    // ➡️ Defines a parameter named 'name'. 
    // property = "sayhello.name" is how you set it from the command line.
    // defaultValue = "World" is the value used if none is provided.
    @Parameter(property = "sayhello.name", defaultValue = "World")
    private String name;

    @Override
    public void execute() throws MojoExecutionException {
        // getLog().info(...) is how your plugin prints messages to the Maven console.
        getLog().info("Hello, " + name + " from my Maven plugin!");
    }
}
```

#### **Understanding Parameters (`@Parameter`)**

The `@Parameter` annotation allows users to configure your plugin goal without changing its Java code.

  * You define a private field (e.g., `private String name;`).
  * The `property` attribute specifies the system property (prefixed with `-D` on the command line) that can set the field's value, like:
      * `mvn ...:say-hello -Dsayhello.name=Ayoub`

-----

### 3\. 💾 Install the Plugin Locally

Before another project can use your newly written plugin, you must compile and install it into your local Maven repository (`~/.m2/repository`).

1.  **Navigate** to your plugin project directory.
2.  **Run the install command:**
    ```bash
    mvn install
    ```
    This command compiles the plugin and places the resulting JAR and its metadata into your local repository.

-----

### 4\. 🚀 Use the Plugin in Another Project

To use your plugin, you need to reference it in the `pom.xml` of the project where you want the custom action to happen.

#### **Manual Invocation (Command Line)**

You can run your goal directly from the command line using the full coordinates of the plugin and the goal name:

```bash
mvn com.example:my-maven-plugin:1.0.0:say-hello
```

  * **`com.example`**: The **Group ID** of the plugin.
  * **`my-maven-plugin`**: The **Artifact ID** of the plugin.
  * **`1.0.0`**: The **Version** of the plugin.
  * **`say-hello`**: The **Goal Name** (Mojo name) you defined.

#### **Automatic Invocation (Binding to a Phase)**

To make your plugin run automatically during a standard Maven build lifecycle, you *bind* its goal to a specific **phase** (e.g., `validate`, `compile`, `package`).

In the target project's `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.example</groupId>
      <artifactId>my-maven-plugin</artifactId>
      <version>1.0.0</version>
      <executions>
        <execution>
          <goals>
            <goal>say-hello</goal> </goals>
          <phase>validate</phase> </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

With this configuration, running `mvn validate` (or any subsequent phase like `mvn install`) will automatically trigger your plugin's `say-hello` goal.

-----

### 5\. 💡 Advanced Plugin Capabilities

Plugins are powerful because they can interact with the entire Maven environment.

| Capability | Explanation | Example Parameter |
| :--- | :--- | :--- |
| **Access Project Model** | Get details about the project being built (e.g., its dependencies, version, name). | `@Parameter(defaultValue = "${project}", readonly = true) private MavenProject project;` |
| **Access Directories** | Get the paths to Maven's standard directories for reading/writing files. | `@Parameter(defaultValue = "${project.build.directory}") private File outputDirectory;` |
| **File Manipulation** | Generate new files (like source code or reports) or modify existing ones within the `target/` directory. | N/A |
| **Tool Integration** | Execute external command-line tools (e.g., code formatters, static analysis tools, code generators). | N/A |

Plugins are essentially **custom automation scripts written in Java** that integrate seamlessly into the standard Maven build lifecycle.

-----

> Would you like to explore how to access the project's dependencies from within your custom plugin?

||
||
||
v

Accessing a project's dependencies from within your custom Maven plugin is essential for tasks like reporting, analysis, or manipulating the classpath.

Here is how you access the project dependencies in your Mojo.

## 🔗 Accessing Project Dependencies in a Mojo

To get information about the dependencies of the project currently being built, you need to inject the **`MavenProject`** object into your Mojo and use a specific annotation.

### 1\. Inject the `MavenProject` Object

The entire project model, including all its dependencies, is encapsulated within the `MavenProject` class. You inject it into your Mojo using the `@Parameter` annotation with a special expression.

In your Mojo Java class, add this private field:

```java
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
// ... other imports

public class YourDependencyMojo extends AbstractMojo {

    /**
     * The MavenProject object representing the project being built.
     */
    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    private MavenProject project;

    // ... rest of your Mojo code
}
```

  * **`@Parameter(defaultValue = "${project}", ...)`**: The `${project}` expression is the key. Maven automatically injects the active project instance into this field.
  * **`readonly = true`**: Indicates that your plugin should only read this object and not try to modify its structure (it's best practice).

-----

### 2\. Retrieve the Dependency Information

Once you have the `MavenProject` object, you can call its methods inside your `execute()` method to retrieve the dependencies.

The `MavenProject` class provides several methods for different sets of dependencies:

| Method | Returns | Description |
| :--- | :--- | :--- |
| **`getDependencies()`** | `List<Dependency>` | Returns the **direct dependencies** as specified *literally* in the project's **`pom.xml`**. This list does **not** include transitive dependencies (dependencies of dependencies). |
| **`getArtifacts()`** | `Set<Artifact>` | Returns **all resolved dependencies**, including both direct and **transitive** dependencies, as a set of **Artifact** objects. This is typically the list you want for execution or analysis. |

### 3\. Example: Listing Direct Dependencies

Here is how you can iterate through the dependencies listed in the `pom.xml`:

```java
import org.apache.maven.model.Dependency;
// ... other imports

@Override
public void execute() throws MojoExecutionException {
    getLog().info("--- Analyzing Project Dependencies ---");

    // 1. Get the list of dependencies defined in the POM
    List<Dependency> dependencies = project.getDependencies();

    if (dependencies.isEmpty()) {
        getLog().info("No direct dependencies found in the project POM.");
        return;
    }

    getLog().info("Direct Dependencies Found:");
    for (Dependency dep : dependencies) {
        String info = String.format("  - %s:%s:%s",
            dep.getGroupId(),
            dep.getArtifactId(),
            dep.getVersion());
        getLog().info(info);
    }
}
```

### 4\. Example: Listing All Resolved Artifacts (Direct + Transitive)

If you need the complete set of dependencies that will be part of the final build classpath (direct + transitive), use `getArtifacts()`:

```java
import org.apache.maven.artifact.Artifact;
import java.util.Set;
// ... other imports

@Override
public void execute() throws MojoExecutionException {
    // ... (project injection is assumed)

    Set<Artifact> artifacts = project.getArtifacts();

    getLog().info("Total Resolved Artifacts (Direct + Transitive): " + artifacts.size());

    for (Artifact artifact : artifacts) {
        String info = String.format("  - %s:%s:%s (Scope: %s)",
            artifact.getGroupId(),
            artifact.getArtifactId(),
            artifact.getVersion(),
            artifact.getScope());
        getLog().debug(info); // Use debug log level for verbosity
    }
}
```
