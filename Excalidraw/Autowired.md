In Spring Framework, "*Dependency Injection*" is just a fancy term for **Spring building your objects for you.**

Imagine Spring is a General Contractor. You give it blueprints (Classes), and it builds the Houses (Beans). To build a house, Spring needs materials (Dependencies like `Repositories`, `Services`, or `Settings`).

Here is how Spring decides how to get those materials inside.

-----

### 1\. The "One Door" Rule (Spring 4.3+)

**The Scenario:** Your class has exactly **one** constructor.

**The Logic:**
Spring looks at your class. It sees that to build this object, there is only one entrance (the constructor). It knows it *must* bring the dependencies through that door to create the object. Because there is no other choice, Spring does it automatically.

**The Code:**
Notice there is no `@Autowired` here. It is clean and works perfectly.

```java
@Component
public class DataInitializer {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // only ONE constructor
    public DataInitializer(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
}
```

> **Plain English Translation:** "Spring, there is only one way to build a `DataInitializer`. Just do it."

-----

### 2\. The "Multiple Doors" Dilemma

**The Scenario:** Your class has **two or more** constructors.

**The Logic:**
Spring looks at the class and sees two entrances. It panics. It asks: *"Do I build the full version using Door A? Or the lite version using Door B?"*

If you don't tell Spring which one to use, the application will crash. You must place `@Autowired` on the constructor you want Spring to use.

**The Code:**
Here, we have a "Production" constructor and a "Testing" constructor.

```java
@Service
public class NotificationService {

    private final EmailSender emailSender;
    private final SmsSender smsSender;

    // Door 1: The Main Entrance
    // We add @Autowired to tell Spring: "USE THIS ONE!"
    @Autowired 
    public NotificationService(EmailSender emailSender, SmsSender smsSender) {
        this.emailSender = emailSender;
        this.smsSender = smsSender;
    }

    // Door 2: The Side Entrance (e.g., for testing)
    // Spring ignores this because it doesn't have the annotation.
    public NotificationService(EmailSender emailSender) {
        this.emailSender = emailSender;
        this.smsSender = null;
    }
}
```

> **Plain English Translation:** "Spring, you have options, so I am forcing you to use Door 1."

-----

### 3\. The "Side Window" (Field & Setter Injection)

**The Scenario:** You aren't using constructors at all. You are putting `@Autowired` directly on the variables (fields) or on setter methods.

**The Logic:**
When you don't use a constructor for injection, Spring builds an **empty object** first. Then, it walks around the house looking for windows marked `@Autowired` to toss dependencies through.

Because this happens *after* the object is built, Spring will **never** do this automatically. You must explicitly add the tag.

**The Code:**

```java
@Service
public class ReportService {

    // Spring creates the class, THEN injects this.
    // @Autowired is MANDATORY here.
    @Autowired
    private UserRepository userRepository; 
}
```

-----

### Summary Checklist

Use this decision tree whenever you are writing a Spring Bean:

| Condition | Action | Why? |
| :--- | :--- | :--- |
| **I have 1 Constructor** | **No Annotation needed.** | Spring implies it. (Best Practice) |
| **I have 2+ Constructors** | **Add `@Autowired` to one.** | To break the tie and remove ambiguity. |
| **I am using Fields/Setters** | **Add `@Autowired` always.** | Spring won't touch fields without permission. |

-----