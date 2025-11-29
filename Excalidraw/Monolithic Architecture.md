```pgsql
				 ┌───────────────────────────────┐
                 │          Browser / App        │
                 │ (User sends HTTP request)     │
                 └──────────────┬────────────────┘
                                │
                                ▼
                 ┌────────────────────────────────┐
                 │     Single Backend Server      │
                 │  (One codebase = all logic)    │
                 │------------------------------- │
                 │  • Routing                     │
                 │  • Controllers / Business Logic│
                 │  • Database Access Layer       │
                 │------------------------------- │
                 │  • Shared Database             │
                 └────────────────────────────────┘
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │          Database            │
                 └──────────────────────────────┘
```

### **Flow**

1.  User request goes to one web server.
    
2.  The monolithic app handles everything (auth, logic, DB queries).
    
3.  A single database stores all data.
    
4.  The app sends one combined response back.
    

**Everything lives together** — one server, one deployment, one database.
