The **`@EventListener`** annotation is a powerful feature in Spring designed to simplify **Event-Driven Programming**. It allows you to create methods that "listen" for specific events occurring within your application and react to them automatically.

It replaces the older, verbose way of implementing the `ApplicationListener` interface with a clean, annotation-based approach.

Here is a detailed breakdown of how it works and a full code example.

---

## 1. 🎬 The Concept: The Observer Pattern

Think of it like a **radio broadcast**:

1. **The Publisher (DJ):** Sends out a signal (an event). The DJ doesn't know who is listening.
    
2. **The Event:** The actual message or song being played.
    
3. **The Listener (`@EventListener`):** The radio in your car. It picks up the signal and plays audio.
    

In Spring:

- **Decoupling:** The Service that triggers an action (like registering a user) doesn't need to know _what_ happens next (sending an email, logging audit data, calculating stats). It just publishes an event, and the listeners handle the rest.
    

---

## 2. 🛠️ Detailed Example: User Registration System

Let's build a scenario where:

1. A user registers.
    
2. We want to **Send a Welcome Email**.
    
3. We want to **Log the activity** for auditing.
    

We will do this using Events so the `UserService` doesn't get cluttered with email and logging logic.

### Step 1: Create the Event Object

This is a simple class that holds the data associated with the event.


```java
package com.example.app.event;

import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class UserRegisteredEvent extends ApplicationEvent {
    private final String username;
    private final String email;

    // Constructor
    public UserRegisteredEvent(Object source, String username, String email) {
        super(source); // 'source' is the object that triggered the event
        this.username = username;
        this.email = email;
    }
}
```

### Step 2: Create the Publisher (The Trigger)

This is usually your Service layer. It uses `ApplicationEventPublisher` to announce that something happened.


```java
package com.example.app.service;

import com.example.app.event.UserRegisteredEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private ApplicationEventPublisher eventPublisher;

    public void registerUser(String username, String email) {
        // 1. Logic to save user to MongoDB...
        System.out.println("💾 User saved to database: " + username);

        // 2. Publish the event
        // This yells to the whole app: "HEY! A USER WAS JUST REGISTERED!"
        UserRegisteredEvent event = new UserRegisteredEvent(this, username, email);
        eventPublisher.publishEvent(event);
    }
}
```

### Step 3: Create the Listeners (`@EventListener`)

These are the components that react to the event. You can have multiple listeners for the same event.


```java
package com.example.app.listener;

import com.example.app.event.UserRegisteredEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Async;

@Component
public class RegistrationListeners {

    // Listener 1: Handles sending the welcome email
    @EventListener
    public void handleWelcomeEmail(UserRegisteredEvent event) {
        // This code runs automatically when 'publishEvent' is called
        System.out.println("📧 Sending welcome email to " + event.getEmail() + "...");
        // Logic to send email via SMTP
    }

    // Listener 2: Handles audit logging
    @EventListener
    public void handleAuditLog(UserRegisteredEvent event) {
        System.out.println("📋 AUDIT: New user registered - " + event.getUsername());
        // Logic to save log to database
    }
}
```

---

## 3. 🧠 How It Works Under the Hood

1. **Startup:** When Spring starts, it scans all beans for methods annotated with `@EventListener`.
    
2. **Registration:** It looks at the **method argument** (e.g., `UserRegisteredEvent event`). It registers that method as a listener for that specific event type.
    
3. **Runtime:** When `eventPublisher.publishEvent(event)` is called:
    
    - Spring intercepts the event.
        
    - It finds all methods listening for that event type.
        
    - It executes those methods.
        

---

## 4. ⚡ Advanced Features (Pro Tips)

### A. Conditional Events

You can use the `condition` attribute with **SpEL (Spring Expression Language)** to only trigger the listener if specific criteria are met.


```java
// Only trigger if the username starts with "admin"
@EventListener(condition = "#event.username.startsWith('admin')")
public void handleAdminRegistration(UserRegisteredEvent event) {
    System.out.println("🚨 ALERT: An Admin just registered!");
}
```

### B. Asynchronous Processing (`@Async`)

By default, `@EventListener` is **synchronous**. This means the `registerUser` method in the Service waits for the email to be sent before it finishes.

If sending an email takes 5 seconds, the user waits 5 seconds. To fix this, use `@Async`:


```java
@Async // Requires @EnableAsync in your config
@EventListener
public void sendEmailAsync(UserRegisteredEvent event) {
    // This runs in a separate thread.
    // The user gets their response immediately, and email sends in background.
}
```

### C. Listening to Built-in Events

You can use `@EventListener` to hook into Spring's lifecycle events (like the ones we discussed earlier):


```java
@EventListener(ApplicationReadyEvent.class)
public void doSomethingAfterStartup() {
    System.out.println("🚀 App is ready to accept requests!");
}
```