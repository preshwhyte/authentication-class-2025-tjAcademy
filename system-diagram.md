# Authentication System Diagram

This diagram shows the step-by-step process for the signup and login endpoints in this project.

## Signup and Login Flow

```mermaid
sequenceDiagram
    autonumber
    participant Client
    participant Express as Express Server<br/>(index.js)
    participant Router as User Routes<br/>(user.routes.js)
    participant Controller as User Controller<br/>(user.controller.js)
    participant BCrypt as BCrypt Library
    participant Model as User Model<br/>(user.models.js)
    participant MongoDB as MongoDB Database<br/>(via Mongoose)

    %% Signup Flow
    rect rgba(56, 182, 255, 0.16)
    Note over Client,MongoDB: SIGNUP PROCESS
    
    Client->>Express: POST /api/users/signup<br/>{name, email, password}
    Express->>Router: Route to /signup endpoint
    Router->>Controller: Call signup()
    
    Controller->>Controller: Validate input fields<br/>(name, email, password)
    
    alt Missing required fields
        Controller-->>Client: 400 Bad Request<br/>"All fields are required"
    else All fields present
        Controller->>Model: findOne({email})
        Model->>MongoDB: Query user by email
        MongoDB-->>Model: Return user or null
        Model-->>Controller: User result
        
        alt User already exists
            Controller-->>Client: 409 Conflict<br/>"User already exists"
        else User does not exist
            Controller->>BCrypt: hash(password, 10)
            BCrypt-->>Controller: hashedPassword
            
            Controller->>Model: Create new User<br/>{name, email, hashedPassword}
            Model->>MongoDB: Save user document
            MongoDB-->>Model: Saved user
            Model-->>Controller: User saved successfully
            
            Controller-->>Client: 201 Created<br/>"User created successfully"
        end
    end
    end

    %% Login Flow
    rect rgba(154, 99, 255, 0.14)
    Note over Client,MongoDB: LOGIN PROCESS
    
    Client->>Express: POST /api/users/login<br/>{email, password}
    Express->>Router: Route to /login endpoint
    Router->>Controller: Call login()
    
    Controller->>Controller: Validate input fields<br/>(email, password)
    
    alt Missing required fields
        Controller-->>Client: 400 Bad Request<br/>"All fields are required"
    else All fields present
        Controller->>Model: findOne({email})
        Model->>MongoDB: Query user by email
        MongoDB-->>Model: Return user or null
        Model-->>Controller: User result
        
        alt User not found
            Controller-->>Client: 404 Not Found<br/>"User not found"
        else User found
            Controller->>BCrypt: compare(password, user.password)
            BCrypt-->>Controller: comparison result
            
            alt Password does not match
                Controller-->>Client: 401 Unauthorized<br/>"Invalid credentials"
            else Password matches
                Controller-->>Client: 200 OK<br/>"Login successful"
            end
        end
    end
    end

    %% Error handling
    rect rgba(255, 99, 132, 0.12)
    Note over Controller,Client: ERROR HANDLING (Both Endpoints)
    Note right of Controller: Any unhandled errors<br/>return 500 Internal Server Error
    end
```

## System Components

### 1. **Client**
   - Sends HTTP requests to the server
   - Endpoints: `POST /api/users/signup` and `POST /api/users/login`

### 2. **Express Server (index.js)**
   - Entry point of the application
   - Configures middleware (express.json, morgan)
   - Connects to MongoDB
   - Routes requests to appropriate routers

### 3. **User Routes (user.routes.js)**
   - Defines API endpoints
   - Maps `/signup` to signup controller
   - Maps `/login` to login controller

### 4. **User Controller (user.controller.js)**
   - Contains business logic for authentication
   - Validates input data
   - Interacts with database through models
   - Handles password hashing and comparison
   - Returns appropriate HTTP responses

### 5. **BCrypt Library**
   - Hashes passwords during signup (salt rounds: 10)
   - Compares plain text passwords with hashed passwords during login

### 6. **User Model (user.models.js)**
   - Defines MongoDB schema (name, email, password)
   - Enforces unique email constraint
   - Includes timestamps

### 7. **MongoDB Database**
   - Stores user documents
   - Handles queries and data persistence

## Flow Summary

### Signup Process (Steps 1-14)
1. Client sends signup request with name, email, password
2. Express routes to signup endpoint
3. Controller validates all required fields
4. Check if user already exists by email
5. If exists, return 409 Conflict
6. If not exists, hash the password using bcrypt
7. Create new user document with hashed password
8. Save to MongoDB
9. Return 201 Created on success

### Login Process (Steps 15-26)
1. Client sends login request with email, password
2. Express routes to login endpoint
3. Controller validates all required fields
4. Find user by email in database
5. If not found, return 404 Not Found
6. If found, compare provided password with stored hash
7. If passwords don't match, return 401 Unauthorized
8. If passwords match, return 200 OK

## HTTP Status Codes

| Code | Meaning | When Used |
|------|---------|-----------|
| 200 | OK | Successful login |
| 201 | Created | User successfully created |
| 400 | Bad Request | Missing required fields |
| 401 | Unauthorized | Invalid credentials during login |
| 404 | Not Found | User not found during login |
| 409 | Conflict | User already exists during signup |
| 500 | Internal Server Error | Unhandled server errors |

## Email Delivery Flow

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant Google as Google Account Security
    participant Env as .env Config
    participant Client as Client App
    participant Express as Express Server<br/>(index.js)
    participant Controller as Auth Controller<br/>(user.controller.js)
    participant EmailService as Email Service<br/>(utils/emailService.js)
    participant Crypto as Crypto Module
    participant Templates as EJS Templates
    participant Transport as Nodemailer Transporter
    participant Gmail as Gmail SMTP
    participant Inbox as User Inbox

    %% Pre-setup: Gmail App Password
    Dev->>Google: Sign in · Navigate to Security · Create App Password
    Google-->>Dev: Return 16-character app password
    Dev->>Env: Store EMAIL_USER & EMAIL_PASS in .env
    Dev->>Express: npm run dev (loads environment variables)
    Express->>EmailService: Initialize transporter with creds
    EmailService->>Transport: createTransport()
    Transport->>Gmail: verify()
    Gmail-->>Transport: 250 Ready to start TLS
    Transport-->>EmailService: Transport ready

    %% Signup Flow
    rect rgba(56, 182, 255, 0.16)
    Note over Client,Inbox: Signup → Welcome email
    Client->>Express: POST /api/users/signup {name,email,password}
    Express->>Controller: signup()
    Controller->>Controller: Validate input · hash password · persist user
    Note right of Controller: OTP stored with 10 min expiry (email currently disabled)
    Controller->>EmailService: sendWelcomeEmail({email,name,loginUrl})
    EmailService->>Templates: render welcome.ejs
    Templates-->>EmailService: Welcome HTML content
    EmailService->>Transport: sendMail(welcome)
    Transport->>Gmail: Transmit SMTP payload
    Gmail-->>Inbox: Deliver welcome message
    Gmail-->>Transport: 250 Accepted
    end

    %% Login Flow
    rect rgba(154, 99, 255, 0.14)
    Note over Client,Inbox: Login → Security notification
    Client->>Express: POST /api/users/login {email,password}
    Express->>Controller: login()
    Controller->>Controller: Verify user & compare password
    Controller->>EmailService: sendLoginNotification({email,name,location,device})
    EmailService->>Templates: render login-notification.ejs
    Templates-->>EmailService: Security HTML content
    EmailService->>Transport: sendMail(login alert)
    Transport->>Gmail: Transmit SMTP payload
    Gmail-->>Inbox: Deliver login notification
    Gmail-->>Transport: 250 Accepted
    end

    %% Forgot Password Flow
    rect rgba(255, 173, 51, 0.16)
    Note over Client,Inbox: Forgot password → Reset token email
    Client->>Express: POST /api/users/forget-password {email}
    Express->>Controller: forgetPassword()
    Controller->>Crypto: randomBytes(32) · sha256(token)
    Crypto-->>Controller: resetToken & hashedToken
    Controller->>Controller: Persist hashed token, expiry, and OTP fallback
    Note right of Controller: Legacy plain-text OTP email sent via config/email
    Controller->>EmailService: sendPasswordResetEmail({email,name,resetToken,resetUrl})
    EmailService->>Templates: render forgot-password.ejs
    Templates-->>EmailService: Reset instructions HTML
    EmailService->>Transport: sendMail(reset)
    Transport->>Gmail: Transmit SMTP payload
    Gmail-->>Inbox: Deliver reset instructions
    Gmail-->>Transport: 250 Accepted
    end

    %% Reset Password Flow
    rect rgba(16, 185, 129, 0.16)
    Note over Client,Inbox: Reset password → Success email
    Client->>Express: POST /api/users/reset-password {token|otp,newPassword}
    Express->>Controller: resetPassword()
    Controller->>Crypto: sha256(token) (when provided)
    Crypto-->>Controller: Hashed token for lookup
    Controller->>Controller: Validate token/OTP · hash new password · clear secrets
    Controller->>EmailService: sendPasswordResetSuccessEmail({email,name,location})
    EmailService->>Templates: render password-reset-success.ejs
    Templates-->>EmailService: Success confirmation HTML
    EmailService->>Transport: sendMail(success)
    Transport->>Gmail: Transmit SMTP payload
    Gmail-->>Inbox: Deliver confirmation email
    Gmail-->>Transport: 250 Accepted
    end

    %% Monitoring & Errors
    Note over EmailService,Gmail: Transport logs successes or errors for each call
```
