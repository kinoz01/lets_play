
## 💡 Why the Spring Boot JAR is Special

A standard JAR file only contains your compiled application classes. The Spring Boot "Fat" JAR is different, which is what allows you to run it directly:

|**Feature**|**Description**|
|---|---|
|**Bundled Dependencies**|The JAR contains **all** of your project's dependencies (Spring Framework, logging, etc.) **nested inside** the main JAR file.|
|**Embedded Server**|The JAR includes the compiled code for the web server (like Tomcat or Jetty).|
|**Custom Launcher**|The plugin modifies the JAR's `MANIFEST.MF` file to specify a custom entry point, usually `org.springframework.boot.loader.JarLauncher`.|

When you execute `java -jar`, the JRE starts the `JarLauncher` class, and this custom class loader knows how to:

1. Read the JAR file.
    
2. Extract the nested dependencies (the "fat" part).
    
3. Set up the internal classpath.
    
4. Launch your application's `main()` method, starting the embedded web server.
    

### Summary of Execution Methods

|**Execution Command**|**Purpose**|**Maven Dependency?**|**Output Location**|
|---|---|---|---|
|`mvn spring-boot:run`|**Development** (Fast, in-place execution)|**Yes** (Requires the plugin)|Runs from `target/classes`|
|`java -jar target/app.jar`|**Production/Deployment** (Final artifact)|**No** (Only needed for the build step)|Runs from the packaged JAR|

The ability to run the JAR directly is one of the most significant advantages of using Spring Boot.