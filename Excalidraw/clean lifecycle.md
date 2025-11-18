## 🧹 The Clean Lifecycle

The purpose of the Clean Lifecycle is simply to **remove files generated during a previous build** to ensure the project is built from a fresh state. It consists of only three phases.

| Phase | Description | Key Goal Bound (Default) |
| :--- | :--- | :--- |
| **`pre-clean`** | Performs actions necessary **before** the project is cleaned. This is often used for logging or custom clean-up tasks. | *(None by default)* |
| **`clean`** | The core phase. **Deletes the build output directory** (typically the `target/` folder and all its contents). | `clean:clean` (from the Maven Clean Plugin) |
| **`post-clean`** | Performs actions necessary **after** the project has been cleaned. | *(None by default)* |

### Example Command

When you run the command `$ mvn clean`, Maven executes the `pre-clean` phase, then the `clean` phase, effectively deleting your `target` directory.
