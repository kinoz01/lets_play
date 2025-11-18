
|Command|Category|Detailed Explanation|
|---|---|---|
|**`mvn clean`**|Lifecycle|**Deletes the `target/` folder**, which contains all compiled classes, packaged JARs, and build artifacts. This ensures you start a fresh build.|
|**`mvn install`**|Lifecycle|Runs **`clean`**, then **`compile`**, **`test`**, **`package`**, and finally **`install`** the result to your local repository. This is the common "build and share locally" command.|
|**`mvn package`**|Lifecycle|Runs **`clean`**, then **`compile`**, **`test`**, and **`package`**. It creates the final JAR/WAR in the `target/` folder but **doesn't** put it in your local repository.|
|**`mvn spring-boot:run`**|Spring Boot|The most common Spring Boot command. As explained above, it runs your application **without creating a JAR file** first, which is fast for development.|
|**`mvn spring-boot:repackage`**|Spring Boot|Used after `mvn package`. It takes the standard JAR and rebuilds it as a "fat JAR" or "executable JAR" (including all necessary dependencies) so you can run it with `java -jar <filename>.jar`. You often run it as **`mvn package spring-boot:repackage`**.|
|**`mvn dependency:tree`**|Dependencies|Prints a **tree-like structure** of all dependencies your project uses, including transitive dependencies (dependencies of your dependencies). This is critical for debugging conflicts.|
|**`mvn help:effective-pom`**|Debug|Shows you the **final, merged `pom.xml` configuration** after all inheritance (from parent POMs) and profile settings have been applied. Essential for advanced debugging.|

> Note that for example the command `mvn clean install` runs phases from **two separate Maven lifecycles**: the **[[Clean Lifecycle]]** and the **Default Lifecycle**.