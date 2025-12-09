When you run `mvn package`, the **Spring Boot Maven Plugin** is automatically executed (specifically, its **`repackage`** goal). This process creates a special artifact known as the **Executable "Fat" JAR**.

***

Maven knows it should use the Spring Boot Maven Plugin and its `repackage` goal during the `package` phase for two main reasons:

## 1. ⚙️ Inheritance from the Parent POM

The most common way a Spring Boot project is set up is by inheriting from the special **`spring-boot-starter-parent`** project. This inheritance is defined at the very beginning of your project's `pom.xml`:


```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.5</version> 
    <relativePath/> 
</parent>
```

This parent POM provides a massive amount of inherited configuration, including **Plugin Management**. Specifically, the parent POM **pre-configures** the `spring-boot-maven-plugin` and **binds** its `repackage` goal to the standard Maven `package` lifecycle phase.

- **Binding:** The parent POM specifies that when the `package` phase is executed, the `spring-boot:repackage` goal _must_ also be executed.
    

---

## 2. 📝 Explicit Plugin Declaration

If you **cannot** or **choose not** to use the `spring-boot-starter-parent` (perhaps because you have another parent POM), you must explicitly declare and configure the plugin in your project's `pom.xml` under the `<build>` section:


```xml
<build>
    <plugins>
        <plugin>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-maven-plugin</artifactId>
            <executions>
                <execution>
                    <goals>
                        <goal>repackage</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
```

In this case, Maven follows the explicit instructions: when the user runs the `package` phase, Maven looks at the `<executions>` defined for this plugin and executes the specified goals (`repackage`).

### Summary

In short, Maven knows to use the plugin because it is either **A)** **Inherited and pre-bound** from the `spring-boot-starter-parent` (most common), or **B)** **Explicitly declared and bound** within your project's own `pom.xml`. This binding process is what turns a generic build command (`mvn package`) into a Spring Boot-specific build command that generates the executable [[Fat JAR]].