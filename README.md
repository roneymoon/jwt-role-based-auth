### Advanced Role-Based Authentication with JWT & MongoDB 🚀

This version includes:  

✅ **User Authentication (Register & Login)** with JWT  

✅ **Role-Based Access Control (Admin & User)**  

✅ **Middleware for Role Authorization**  

✅ **Scalable Folder Structure**

#### 1 - Installing Dependencies

```sh
npm install express mongoose bcryptjs jsonwebtoken dotenv cors
```

#### 2 - Project Folder Structure

```jsx
/auth-app
│── /config
│   ├── db.js
│── /middleware
│   ├── authMiddleware.js
│   ├── roleMiddleware.js
│── /models
│   ├── User.js
│── /routes
│   ├── authRoutes.js
│   ├── adminRoutes.js
│   ├── userRoutes.js
│── .env
│── server.js
```

#### 3 - Database Configuration

→ `require('dotenv').config()` This line **loads environment variables** from a `.env` file into `process.env` in your Node.js application.

###### `useNewUrlParser: true`

- Ensures Mongoose **parses MongoDB connection strings correctly**.

- Prevents errors due to **deprecations in the native MongoDB driver**.

###### `useUnifiedTopology: true`

- Enables **new connection management engine** in MongoDB.

- Improves **stability** and **performance** by removing outdated polling mechanisms.

```jsx
const mongoose = require('mongoose');
require('dotenv').config();

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('🔥 MongoDB Connected'))
.catch(err => console.log('❌ DB Connection Error:', err));
```


---
#### 4 - User-Model (models/User.js)

This file defines the **User schema and model** using Mongoose, which allows interaction with a MongoDB database in a structured way.

→ Loading Mongoose, which is an **ODM (Object Data Modeling) library** for MongoDB.

→ Mongoose helps define **schemas and models** for structured data storage.

→ **`mongoose.Schema({...}, { collection: 'user' })`** creates a **structure for documents** in the `user` collection.

```jsx
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    // Role-based access
    role: { type: String, enum: ['user', 'admin'], default: 'user' } 
});

module.exports = mongoose.model('User', userSchema);
```

🚀 **This is the backbone of user authentication in your app!**

---

####  5 - Authentication Middleware (`middleware/authMiddleware.js`)

This middleware handles **authentication** by verifying JWT (JSON Web Token) from incoming requests. `jsonwebtoken` is used to create and verify JWTs.

The **JWT is usually sent in the `Authorization` header** as:

```jsx
Authorization: Bearer <token>
```

→ `?.split(' ')[1]` → Extracts the **actual token** after "Bearer".

→ `jwt.verify(token, secret_key)` Checks if the token is **valid and not expired `process.env.JWT_SECRET`** is used for security.

```js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access Denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or Expired Token' });
    }
};

module.exports = authMiddleware;
```

##### 🔥 Importance of This Middleware

✅ **Protects private routes** by requiring valid authentication.  

✅ **Extracts and verifies JWT** from the request.  

✅ **Prevents access to unauthorized users** (missing, expired, or modified tokens).  

✅ **Stores user info in `req.user`** for further use (e.g., role-based access).

---
#### 6 - Role-Based Middleware (`middleware/roleMiddleware.js`)

This middleware **restricts access** to certain routes based on **user roles**. 

It ensures that only users with specific roles (like `admin`) can access protected endpoints.

The syntax of the **`return (req, res, next) => { ... }`** inside `roleMiddleware(roles)` is a **higher-order function**. 

`roleMiddleware` is a Function that Returns Another Function.

`roleMiddleware(roles)` is a **function that takes `roles` (an array of allowed roles) as an argument**. It **returns another function** that acts as **middleware**.

→ `req.user.role` is **extracted from the decoded JWT** (set by `authMiddleware`).

→ `next()` If the role is valid, **proceed to the next middleware or route handler**.

```js
const roleMiddleware = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
        }
        next();
    };
};

module.exports = roleMiddleware;
```

This is essential for access control in apps! 

##### How to use in Routes ?

```jsx
router.get("/admin-dashboard", authMiddleware, roleMiddleware(['admin']), (req, res) => {
    res.json({ message: "Welcome to Admin Dashboard" });
});
```

- First, **`authMiddleware`** ensures the user is logged in.

- Then, **`roleMiddleware(['admin'])`** ensures only **admins** can access.

##### 🔥 Importance of This Middleware

✅ **Enforces role-based security** in your application.  

✅ **Ensures only authorized users** access protected resources.  

✅ **Works alongside `authMiddleware`** to check both authentication & authorization.  

✅ **Flexible and reusable** → Can define multiple roles in one function.

---
#### 7 - Authentication Routes (`routes/authRoutes.js`)

This file defines **user authentication routes** for **registration and login** using Express.js. It integrates **bcrypt.js** for password hashing and **jsonwebtoken (JWT)** for user authentication.

###### Registering User `post /register` What It Does ?  

✅ Extracts `username`, `email`, `password`, and `role` from the request body.  
✅ **Hashes the password** using `bcrypt.hash(password, 10)`.  
✅ Creates a new `User` object and saves it in MongoDB.  
✅ Sends a **201 (Created)** response on success.  
❌ **Catches errors** and returns a **500 (Server Error)** if registration fails.

###### Logging-In User `post /login` What it Does ?

✅ Extracts `email` and `password` from the request.  
✅ **Finds the user** in the MongoDB database using `User.findOne({ email })`.  
✅ **Compares the entered password** with the hashed password using `bcrypt.compare()`.  
✅ **Generates a JWT token** with `userId`, `username`, and `role` (expires in 1 hour).  
✅ Returns the **JWT token** on successful login.  
❌ If the user **doesn’t exist** or the password **doesn’t match**, it returns `401 (Unauthorized)`. 
❌ **Handles errors** and sends `500 (Server Error)` if login fails.

```jsx
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
require('dotenv').config();

const router = express.Router();

// **Register User**
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User(
	        { username, email, password: hashedPassword, role }
	    );

        await user.save();
        res.status(201).json({ message: 'User registered successfully!' });

    } catch (error) {
        res.status(500).json({ message: 'Error registering user', error });
    }
});

// **Login User**
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid Credentials' });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.json({ message: 'Login successful', token });

    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error });
    }
});

module.exports = router;
```

This `authRoutes.js` file is **essential** for handling **secure user authentication** in a role-based system.

---

#### 8 - Protected Admin Routes (`routes/adminRoutes.js`)

This file defines **protected routes** that only **authenticated admins** can access. It ensures **security** by using authentication and role-based access control (RBAC).

```js
const express = require('express');
const authMiddleware = require('../middleware/authMiddleware');
const roleMiddleware = require('../middleware/roleMiddleware');

const router = express.Router();

// **Admin Only Route**
router.get('/dashboard', authMiddleware, roleMiddleware(['admin']), (req, res) => {
    res.json({ message: 'Welcome to Admin Dashboard', user: req.user });
});

module.exports = router;
```

###### Dashboard Route `GET /dashboard`

✅ **First, `authMiddleware` checks if the user is logged in** using a valid **JWT token**.  
✅ **Then, `roleMiddleware(['admin'])` ensures only admin users** can access this route.  
✅ If both conditions pass, it responds with **a success message and user details**.  
❌ If the user **is not authenticated**, they receive a **401 Unauthorized** error.  
❌ If the user **is not an admin**, they receive a **403 Forbidden** error.

This `adminRoutes.js` file is **critical** for maintaining **secure admin-only functionalities**

---
#### 9 - Protected User Routes (`routes/userRoutes.js`)

```js
const express = require('express');
const authMiddleware = require('../middleware/authMiddleware');

const router = express.Router();

// **User Dashboard**
router.get('/profile', authMiddleware, (req, res) => {
    res.json({ message: 'Welcome to your Profile', user: req.user });
});

module.exports = router;
```

###### Profile Route `GET /profile`

✅ **First, `authMiddleware` checks if the user is authenticated** using a **valid JWT token**.  
✅ If authenticated, the route responds with **a success message and user details**.

---

#### 10 - Main Server File (`server.js`)**

This is the **entry point** of the application, where the Express server is set up and routes are managed.

✅ **`cors`** → Enables Cross-Origin Resource Sharing (CORS) to **allow API requests** from different domains.  

✅ **`dotenv.config()`** → Loads environment variables from a `.env` file.  

✅ **`require('./config/db')`** → **Connects** to MongoDB by importing the **database configuration.**

```js
const express = require('express');
const cors = require('cors');
require('dotenv').config();
require('./config/db'); // Connect to MongoDB

const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();

app.use(express.json());
app.use(cors());

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/user', userRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
```

This `server.js` file is the **core of the backend**, managing routes and configurations for seamless API operations. 🚀🔥

---

#### `.env` File (Environment Variables)

```
PORT=5000
MONGO_URI=mongodb+srv://your_mongo_uri
JWT_SECRET=your_secret_key
```

---

### **🔥 How It Works:**

1️⃣ **Register Users & Admins**

```http
POST /api/auth/register
{
  "username": "admin_user",
  "email": "admin@example.com",
  "password": "securepassword",
  "role": "admin"
}
```

```http
POST /api/auth/register
{
  "username": "normal_user",
  "email": "user@example.com",
  "password": "securepassword",
  "role": "user"
}
```

2️⃣ **Login & Get Token**

```http
POST /api/auth/login
{
  "email": "admin@example.com",
  "password": "securepassword"
}
```

📌 **Response:**

```json
{
  "message": "Login successful",
  "token": "eyJhbGciOiJIUzI1..."
}
```

3️⃣ **Access Protected User Route**

```http
GET /api/user/profile
Headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1..." }
```

📌 **Response:**

```json
{
  "message": "Welcome to your Profile",
  "user": { "userId": "64ac12f...", "username": "normal_user" }
}
```

4️⃣ **Access Protected Admin Route (Fails for Non-Admins)**

```http
GET /api/admin/dashboard
Headers: { "Authorization": "Bearer eyJhbGciOiJIUzI1..." }
```

📌 **If User is NOT Admin:**

```json
{ "message": "Forbidden: Insufficient permissions" }
```

📌 **If User is Admin:**

```json
{
  "message": "Welcome to Admin Dashboard",
  "user": { "userId": "64ac12f...", "username": "admin_user" }
}
```

---

##### Why This is Scalable?

✔ **Modular File Structure**  
✔ **Role-Based Access Control**  
✔ **JWT Authentication**  
✔ **MongoDB Integration**  
✔ **Middleware for Security & Authorization**

---
#### 🔥 Add **Rate Limiting** to Your API 🚀

We'll use **express-rate-limit** to prevent abuse and enhance security.

Install Rate-Limit Package

```sh
npm install express-rate-limit
```

###### Create a Rate-Limiting Middleware

Create a new file **`middleware/rateLimiter.js`**

```jsx
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests from this IP, please try again later.' },
    headers: true, // Send rate limit headers
});

module.exports = apiLimiter;
```

###### 📌 What Does `headers: true` Do?

When enabled, it includes **rate limit headers** in the HTTP response, such as:

1️) **`X-RateLimit-Limit`** → Maximum number of requests allowed.  

2️) **`X-RateLimit-Remaining`** → Remaining requests in the current window.  

3️) **`X-RateLimit-Reset`** → Time (in seconds) until the limit resets.

---
###### Applying Rate Limiting to Routes

modifying the server.js

```jsx
...
// Import Rate Limiter
const rateLimiter = require('./middleware/rateLimiter'); 

const app = express();

app.use(express.json());
app.use(cors());

app.use(rateLimiter); // Apply rate limiting globally
// OR apply to specific routes
// app.use('/api/auth', rateLimiter, authRoutes);

...
```

After **100 requests within 15 minutes**, further requests will return:

```json
{
  "error": "Too many requests from this IP, please try again later."
}
```

### **🔥 Summary:**

✅ **Global API Rate Limiting** (100 requests per 15 minutes)  

✅ **Custom Rate Limit for Login Attempts** (5 attempts per 5 minutes)  

✅ **Prevents Abuse, Brute Force & DDoS Attacks**

in Future if you want you can implement **IP whitelisting** or **Redis-based rate limiting** 🚀

---
###### Author: **Roney Moon**
###### Date: **26-02-2025**

### Keep coding, keep securing, and happy building! 💙
