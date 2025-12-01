
## 1\. Request Enters Tomcat (Servlet Container)


Tomcat receives the request on port `8080`.  
Tomcat looks at its servlet mappings and finds that the `DispatcherServlet` is mapped to `/` (all requests).

Tomcat calls:

```scss
dispatcherServlet.service(request, response)
```

This is the start.

---

## 2\. DispatcherServlet Calls `doDispatch()`


The main method of the entire web layer:

```scss
DispatcherServlet.doDispatch()
```

This performs the whole request handling.

Inside `doDispatch()`, these steps happen:

---

## 3\. Find the Matching `@Controller` Method (HandlerMapping)


`DispatcherServlet` asks all registered `HandlerMapping` beans:

"Which controller method should handle this request?"

Examples of handler mappings:

-   `RequestMappingHandlerMapping`
    
-   `SimpleUrlHandlerMapping`
    

If you have:

```kotlin
@GetMapping("/users")
```

`HandlerMapping` will say:  
“Request `/users` matches `UsersController.getUsers()`”

Result:  
A `HandlerMethod` object describing which controller method to call.

---

## 4\. Find the Right `HandlerAdapter`


Not all handlers are methods.  
Some are controllers, some are functions.

`DispatcherServlet` asks all `HandlerAdapter`s:

"Which adapter can execute this handler?"

For `@Controller` and `@RestController` methods:

-   `RequestMappingHandlerAdapter` is chosen.
    

This adapter knows how to:

-   resolve method parameters
    
-   invoke the method
    
-   process return values
    

---

## 5\. Resolve Method Arguments (`HandlerMethodArgumentResolver`)


Before calling the controller method, Spring prepares the arguments.

Examples:

-   `@RequestParam`
    
-   `@PathVariable`
    
-   `@RequestBody`
    
-   `HttpServletRequest`
    
-   `HttpSession`
    
-   `@ModelAttribute`
    

Each type is handled by a `HandlerMethodArgumentResolver`.

Flow:  
`DispatcherServlet` → `HandlerAdapter` → `ArgumentResolvers` → Controller Method Arguments

---

## 6\. Invoke the Controller Method


Now Spring calls your method:

```javascript
Object result = controllerMethod.invoke(arguments...)
```

The method returns either:

-   a Java object → JSON response
    
-   `ResponseEntity`
    
-   `String` → view name
    
-   `ModelAndView`
    
-   `void`
    
-   `HttpEntity`
    

`DispatcherServlet` does not process this result directly.

It delegates again.

---

## 7\. Handle the Return Value (`HandlerMethodReturnValueHandler`)


Spring must convert the controller return value into a web response.

It uses `HandlerMethodReturnValueHandler`s.

Examples:

-   `@ResponseBody` → write JSON using `HttpMessageConverter`s
    
-   `String` → resolve view name
    
-   `ModelAndView` → render view template
    

For REST controllers:

-   `RequestResponseBodyMethodProcessor` is used
    
-   It converts your object to JSON using Jackson
    

---

## 8\. Message Conversion to JSON/XML (`HttpMessageConverter`)


If the controller returns an object:

```sql
return new User("Ayoub");
```

Spring selects the correct `HttpMessageConverter`:

-   `MappingJackson2HttpMessageConverter` for JSON
    
-   `Jaxb2RootElementHttpMessageConverter` for XML
    

The object becomes JSON written to the `HttpServletResponse` output stream.

---

## 9\. Exception Handling (`HandlerExceptionResolver`)


If the controller throws an exception:

```cpp
throw new UserNotFoundException();
```

`DispatcherServlet` does not crash.  
It delegates to `HandlerExceptionResolver`s.

These convert exceptions into:

-   Error JSON
    
-   Error pages
    
-   `ResponseEntity`
    

Examples:

-   `@ControllerAdvice` + `@ExceptionHandler`
    
-   `DefaultHandlerExceptionResolver`
    

---

## 10\. View Resolution (If MVC HTML App) (`ViewResolver`)



If the controller returns:

```kotlin
return "home";
```

`DispatcherServlet` asks `ViewResolver`s:

"Which view template corresponds to `home`?"

Examples:

-   `ThymeleafViewResolver`
    
-   `InternalResourceViewResolver` (JSP)
    

The view is rendered into HTML and written to the response.

---

## 11\. Send the Response Back to Tomcat


Finally:

`HttpServletResponse` contains:

-   status
    
-   headers
    
-   body (JSON/HTML/text)
    

`DispatcherServlet` returns control to Tomcat.

Tomcat writes the response back to the client.

---

## Summary of the Internal Flow


1.  Tomcat receives request
    
2.  Tomcat calls `DispatcherServlet`
    
3.  `doDispatch()` begins
    
4.  Find controller using `HandlerMapping`
    
5.  Find `HandlerAdapter`
    
6.  Resolve method arguments
    
7.  Invoke controller method
    
8.  Handle return value
    
9.  Convert object → JSON (`HttpMessageConverter`)
    
10.  Exception handling if needed (`HandlerExceptionResolver`)
    
11.  View rendering if MVC HTML (`ViewResolver`)
    
12.  Write response to `HttpServletResponse`
    
13.  Return to client
    
