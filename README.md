 Traffic Log Analyzer

Project Overview
Traffic Log Analyzer is a **Java-based console application** that processes and analyzes web server log files.  
It helps system administrators, developers, and security teams understand website traffic patterns, top visitors, and common errors.

 Features
- Read and parse server log files
- Identify **most visited URLs**
- Find **frequent visitors (by IP)**
- Summarize **HTTP status codes**
- Exception handling for invalid/corrupted logs
- Scalable design for adding new log formats

 Target Users
- System Administrators
- Web Developers
- Cybersecurity Teams
- Website Owners

OOP Concepts Used
- **Encapsulation** → Log details in `LogEntry` class (private fields + getters/setters)  
- **Inheritance** → Extend base analyzer into specific analyzers  
- **Polymorphism** → Method overriding for different log formats  
- **Abstraction** → High-level `analyze()` methods hide parsing complexity  
- **Composition** → Analyzer class uses multiple `LogEntry` objects  


UML Class Diagram
![Class Diagram](./diagrams/class_diagram.png)

 Review 1 Deliverables
- ✅ Project Title & Description  
- ✅ Problem Statement & Target Users  
- ✅ UML Class Diagram  
- ✅ OOP Concepts Explanation  
- ✅ Repo initialized with README.md  

Tech Stack
- Java (Console-based Application)
- UML for Class Diagram
- GitHub for version control


