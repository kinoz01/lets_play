Here’s a comparison of a **"Hello World"** application in **Spring Framework** vs **Spring Boot**, showing the differences in setup and structure.

---

## 🌱 Spring Framework "Hello World"

Spring (without Boot) requires more configuration, including a `web.xml` or Java-based configuration, and manual setup of a `DispatcherServlet`.

### ✅ Java Config + Spring MVC Example

**1\. Maven Dependencies (pom.xml):**

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-webmvc</artifactId>
        <version>5.3.34</version> <!-- latest for Spring Framework 5 -->
    </dependency>
    <dependency>
        <groupId>javax.servlet</groupId>
        <artifactId>javax.servlet-api</artifactId>
        <version>4.0.1</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```

**2\. WebAppInitializer (replaces web.xml):**

```java
public class AppInitializer implements WebApplicationInitializer {
    @Override
    public void onStartup(ServletContext servletContext) {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.register(AppConfig.class);
        DispatcherServlet servlet = new DispatcherServlet(context);
        ServletRegistration.Dynamic registration = servletContext.addServlet("dispatcher", servlet);
        registration.setLoadOnStartup(1);
        registration.addMapping("/");
    }
}
```

**3\. AppConfig (Spring Configuration):**

```java
@Configuration
@EnableWebMvc
@ComponentScan(basePackages = "com.example")
public class AppConfig {
}
```

**4\. Controller:**

```java
@Controller
public class HelloController {
    @RequestMapping("/")
    @ResponseBody
    public String hello() {
        return "Hello World from Spring!";
    }
}
```

**5. Build the WAR File**

In terminal (from the project root):

```bash
mvn clean package
```

This will generate a `spring-hello-world.war` file in the `target/` directory.


**6. Deploy WAR to Apache Tomcat**

*A. Download and Install Tomcat

-   Download Tomcat from: [https://tomcat.apache.org](https://tomcat.apache.org)
    
-   Extract it (e.g., to `C:\apache-tomcat-9.0.84` or similar)
    

 *B. Deploy WAR

-   Copy `target/spring-hello-world.war` into `tomcat/webapps/`
    

 *C. Start Tomcat

-   Run `startup.sh` (Linux/macOS) or `startup.bat` (Windows)
    

*D. Access the App

Open browser:

```bash
http://localhost:8080/spring-hello-world/
```

You should see:

```csharp
Hello World from Spring!
```
---

## 🚀 Spring Boot "Hello World"

Spring Boot minimizes configuration. It uses embedded servers (Tomcat by default) and auto-configuration.

**1\. Maven Dependencies (pom.xml):**

```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

**2\. Application class with Controller:**

```java
@SpringBootApplication
@RestController
public class HelloWorldApplication {

    public static void main(String[] args) {
        SpringApplication.run(HelloWorldApplication.class, args);
    }

    @GetMapping("/")
    public String hello() {
        return "Hello World from Spring Boot!";
    }
}
```

---

### ✅ Key Differences

| Feature | Spring | Spring Boot |
| --- | --- | --- |
| Setup | Manual configuration | Auto-configuration |
| Embedded Server | No (external Tomcat/Jetty) | Yes (Tomcat by default) |
| Dependencies | Select manually | Starters simplify setup |
| Boilerplate | More | Minimal |
| Dev Tools | Manual | Built-in with `spring-boot-devtools` |
