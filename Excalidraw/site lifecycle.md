## 📄 The Site Lifecycle

The purpose of the Site Lifecycle is to **create and deploy project documentation**. This includes reports, Javadocs, test results, and general project information that's often published to a web server. It consists of four phases.

| Phase | Description | Key Goal Bound (Default) |
| :--- | :--- | :--- |
| **`pre-site`** | Performs actions necessary **before** the site documentation is generated. | *(None by default)* |
| **`site`** | The core phase. **Generates the project documentation** based on the configuration in the `pom.xml` (using reporting plugins). The documentation is placed in the `target/site` directory. | `site:site` (from the Maven Site Plugin) |
| **`post-site`** | Performs actions necessary **after** the site documentation has been generated. | *(None by default)* |
| **`site-deploy`** | **Copies the generated site documentation** to a remote web server (defined in the `pom.xml`'s `<distributionManagement>` section). | `site:deploy` (from the Maven Site Plugin) |

### Example Command

When you run the command `$ mvn site`, Maven executes `pre-site`, then the `site` phase, generating all the documentation into the `target/site` folder.

If you then run `$ mvn site-deploy`, it will take that generated documentation and upload it to the designated server.