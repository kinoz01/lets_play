## 🚀 What is Apache Maven?

In plain English, **Maven** is a **build automation and project management tool** primarily for Java projects. Think of it as a sophisticated manager for your entire software project.

In the past, developers had to manually handle tasks like compiling code, packaging it, and finding the necessary third-party libraries (dependencies). Maven automates all this, following the principle of **Convention over Configuration**. This means it assumes a standard project structure (e.g., source code in `src/main/java`) so you spend less time configuring things and more time coding.

### Key Concepts

* **Project Object Model (POM):** This is the heart of a Maven project. It's an **XML file named `pom.xml`** located in the root directory. The POM describes the project, its dependencies (libraries it needs), the build lifecycle, and the plugins to use.
* **Dependency Management:** This is perhaps Maven's most valuable feature. Instead of manually downloading JAR files, you simply declare the library (dependency) in your `pom.xml`. Maven automatically downloads the correct version of the library—and all the libraries that library needs (transitive dependencies)—from a public repository (like Maven Central) and stores them in your local repository (`~/.m2/repository`).
* **Plugins and Goals:** Maven is a **plugin execution framework**. All the actual work—compiling, testing, packaging—is done by **plugins**. A plugin is a collection of **goals** (specific tasks). For example, the `maven-compiler-plugin` has a `compile` goal.
* **Build Lifecycles and Phases:** The build process is structured into **lifecycles**, which are made up of sequential **phases**. When you run a command like `mvn package`, Maven executes all the phases *up to and including* the `package` phase in the correct order.

---

## 2. Maven and Its Execution Flow

The `mvn` command (or the wrapper script `./mvnw`) is the entry point for running Maven.

### When running the command `mvn` or  the script `./mvnw`

1.  **Environment Check:** The script first checks the system environment to locate the **Java Runtime Environment (JRE)** or **Java Development Kit (JDK)**, as Maven itself is a Java application.
2.  **Maven Home Detection:** It locates the main Maven installation directory (`M2_HOME`).
3.  **Command Execution:** It takes the goals or phases you provided (e.g., `clean install`) and passes them, along with necessary configuration flags, to the main Maven Java program.
4.  **Launching the JVM:** Essentially, the script executes a long Java command like this (simplified):

    > `java -classpath <Maven_Home>/boot/* -Dmaven.home=<Maven_Home> org.codehaus.plexus.classworlds.launcher.Launcher <goals>`

### Detailed Execution Sequence

1.  **Read `pom.xml`:** Maven reads the project's **POM**.
2.  **Resolve Dependencies:** It checks the dependencies listed in the POM. For any missing dependencies, it downloads them from remote repositories and stores them in the **local repository** (`~/.m2/repository`).
3.  **Execute Phases/Goals:** Maven begins executing the requested phases in the correct order (e.g., for `install`: `validate` → `compile` → `test` → `package` → `install`).
4.  **Plugin Invocation:** As Maven hits each phase, it triggers the **goals** bound to that phase from the necessary plugins (e.g., the `maven-compiler-plugin:compile` goal runs during the `compile` phase).