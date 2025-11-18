## 🛠️ Maven Wrapper (`mvnw`) vs. Maven (`mvn`)

Think of the Maven Wrapper as a project-specific intermediary that guarantees consistency.

| Feature | Maven Wrapper (`mvnw`) | Standard Maven (`mvn`) |
| :--- | :--- | :--- |
| **Type** | A script (shell or batch) included in a project. | The main, globally installed Maven executable. |
| **Purpose** | Ensures the project uses a **specific, configured version** of Maven. It automatically downloads and installs that version if it's missing. | Executes Maven builds using the **system's installed** Maven version. |
| **Installation** | Requires only a JRE/JDK on the machine; Maven itself is downloaded by the wrapper. | Requires a full, separate installation of Maven configured on the system's PATH. |
| **Consistency** | **High** - ensures all developers and CI/CD pipelines use the exact same Maven version. | **Low** - depends on the version installed on each machine, which can lead to "it works on my machine" issues. |

### Why Use `mvnw`?

The primary benefit of the Maven Wrapper is **reproducible builds** and **ease of onboarding**.

* **Version Control:** The specific Maven version is defined in the project's configuration file (`.mvn/wrapper/maven-wrapper.properties`) and is committed to version control.
* **Zero Setup:** New developers can clone the project and run `./mvnw clean install` without needing to install or configure Maven first. The wrapper takes care of downloading the correct one.

In short, when you use **`./mvnw clean install`**, the script first checks for the specific version of Maven, downloads it if necessary, and *then* uses that downloaded version to execute the Maven command. When you use **`mvn clean install`**, you are relying on whatever Maven version is already available on your system's PATH.