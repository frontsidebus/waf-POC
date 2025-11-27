```mermaid
%%{init: {'theme': 'dark'}}%%
graph TD
    %% External Entities
    subgraph External["External World"]
        User(("User (Browser)"))
        Admin(("Administrator"))
        Google(("Google OAuth"))
    end

    %% Docker Container Network
    subgraph DockerNet["Docker Network"]
        direction TB
        
        %% Services
        Input["Input Filter Service<br>(Port 8080)"]
        Output["Output Filter Service<br>(Port 8081)"]
        Policy["Policy & Logger Service<br>(Port 5000)"]
        OWUI["OpenWebUI Container<br>(Internal)"]
        
        %% Data Store - CHANGED to MongoDB
        DB[("MongoDB Container<br>(Rules & Logs)")]
    end

    %% --- Main Request Flow ---
    User -- "1. Send Prompt (HTTP POST)" --> Input
    
    %% Input Filtering Logic
    Input -. "2. Fetch Input Rules (API)" .-> Policy
    Input -- "3a. [BLOCKED] Log Event" --> Policy
    Input -- "3b. [ALLOWED] Forward Request" --> Output

    %% Output Filtering Logic
    Output -. "4. Fetch Output Rules (API)" .-> Policy
    Output -- "5. Forward Request" --> OWUI
    OWUI -- "6. Raw LLM Response" --> Output
    Output -- "7a. [SENSITIVE DATA] Log & Redact" --> Policy
    Output -- "7b. [SAFE] Forward Response" --> Input
    
    Input -- "8. Return Response" --> User

    %% --- Management Flow ---
    Admin -- "9. Access Dashboard" --> Policy
    Policy -- "10. Authenticate" <--> Google
    Policy <--> DB

    %% Styling
    classDef service fill:#330066,stroke:#9932cc,stroke-width:2px,color:#fff;
    classDef storage fill:#2f4f4f,stroke:#d3d3d3,stroke-width:2px,color:#fff;
    classDef external fill:#1a1a1a,stroke:#ffffff,stroke-width:3px,color:#fff;
    
    class Input,Output,Policy,OWUI service;
    class DB storage;
    class User,Admin,Google external;