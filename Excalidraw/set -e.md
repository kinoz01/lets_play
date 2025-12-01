`set -e` is a crucial command in shell scripting that significantly changes how your script handles **errors**.

In short, it tells the shell: **"Exit immediately if a command exits with a non-zero status."**

This feature is often called "errexit" or "fail-fast."

---

## 🛑 Understanding the Default Behavior

By default, when a command in a shell script fails, the shell simply prints an error message and continues executing the next line of the script. This can lead to silent failures where subsequent commands run using partial, incorrect, or missing data.

- **Example (Default Behavior):**
    
    1. `rm non_existent_file.txt` (This fails with an error status).
        
    2. `echo "Cleanup done."` (This still runs, even though the intended cleanup failed).
        

---

## ✅ What `set -e` Changes

When you place `set -e` (or the longer equivalent `set -o errexit`) at the beginning of your script, you enable the fail-fast behavior. The script will **immediately terminate** if any command returns an exit status that is **not 0**.

- **Exit Status 0:** Success (the script continues).
    
- **Exit Status Non-zero (e.g., 1, 2, 127):** Failure (the script stops immediately).
    

### Example with `set -e`


```bash
#!/bin/bash
set -e # Enable fail-fast behavior

# Command 1: Success (Exit Status 0)
mkdir my_new_directory 

# Command 2: Failure (Exit Status 1)
rm non_existent_file.txt 

# Command 3: This command will NOT run
echo "Cleanup done." 
```

In this example, the script stops at Command 2, preventing Command 3 from executing on a potentially inconsistent system state.

---

## 🛠️ Best Practice

It is generally considered a **best practice** in robust shell scripting to start your scripts with the following line, often called the "unofficial strict mode" header:

```bash
set -euo pipefail
```

- **`set -e` (errexit):** Exit immediately if a command exits with a non-zero status.
    
- **`set -u` (nounset):** Treat unset variables as an error (prevents accidental bugs from typos).
    
- **`set -o pipefail` (pipefail):** Ensure that a pipeline fails if _any_ command in the pipeline fails, rather than just using the exit status of the _last_ command.


[[set -a]]