const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secure-secret-key-change-in-production';
const JWT_EXPIRES_IN = '15m'; // 15 minutes

// Middleware
app.use(express.json());

// File-based user storage
const USERS_FILE = path.join(__dirname, 'users.json');

if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, JSON.stringify([]));
}

const getUsers = () => {
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading users file:', error);
        return [];
    }
};

const saveUsers = (users) => {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    } catch (error) {
        console.error('Error saving users file:', error);
    }
};

const findUserByUsername = (username) => {
    const users = getUsers();
    return users.find(user => user.username === username);
};

const findUserById = (id) => {
    const users = getUsers();
    return users.find(user => user.id === id);
};

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ 
            error: 'Access token required',
            message: 'Please provide a valid JWT token in the Authorization header' 
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ 
                    error: 'Token expired',
                    message: 'Your session has expired. Please log in again.' 
                });
            }
            return res.status(403).json({ 
                error: 'Invalid token',
                message: 'The provided token is invalid or malformed' 
            });
        }
        req.user = user;
        next();
    });
};

// Routes

// POST /register - Create a new user
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validation
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'Missing required fields',
                message: 'Username and password are required' 
            });
        }

        if (username.length < 3) {
            return res.status(400).json({ 
                error: 'Invalid username',
                message: 'Username must be at least 3 characters long' 
            });
        }

        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'Invalid password',
                message: 'Password must be at least 6 characters long' 
            });
        }

        // Check if user already exists
        const existingUser = findUserByUsername(username);
        if (existingUser) {
            return res.status(409).json({ 
                error: 'User already exists',
                message: 'A user with this username already exists' 
            });
        }

        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create new user
        const users = getUsers();
        const newUser = {
            id: Date.now().toString(), // Simple ID generation
            username: username.toLowerCase().trim(),
            password: hashedPassword,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        saveUsers(users);

        // Return success response (without password)
        const { password: _, ...userResponse } = newUser;
        res.status(201).json({
            message: 'User created successfully',
            user: userResponse
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'An error occurred during registration' 
        });
    }
});

// POST /login - Authenticate user and return JWT
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validation
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'Missing credentials',
                message: 'Username and password are required' 
            });
        }

        // Find user
        const user = findUserByUsername(username.toLowerCase().trim());
        if (!user) {
            return res.status(401).json({ 
                error: 'Invalid credentials',
                message: 'Invalid username or password' 
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ 
                error: 'Invalid credentials',
                message: 'Invalid username or password' 
            });
        }

        // Generate JWT
        const tokenPayload = {
            id: user.id,
            username: user.username
        };

        const token = jwt.sign(tokenPayload, JWT_SECRET, { 
            expiresIn: JWT_EXPIRES_IN 
        });

        // Return success response
        res.json({
            message: 'Login successful',
            token: token,
            expiresIn: JWT_EXPIRES_IN,
            user: {
                id: user.id,
                username: user.username,
                createdAt: user.createdAt
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'An error occurred during login' 
        });
    }
});

// GET /profile - Protected route that returns user information
app.get('/profile', authenticateToken, (req, res) => {
    try {
        // Find user by ID from token
        const user = findUserById(req.user.id);
        
        if (!user) {
            return res.status(404).json({ 
                error: 'User not found',
                message: 'The user associated with this token no longer exists' 
            });
        }

        // Return user profile (without password)
        const { password: _, ...userProfile } = user;
        res.json({
            message: 'Profile retrieved successfully',
            user: userProfile
        });

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            message: 'An error occurred while retrieving profile' 
        });
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        message: 'JWT Authentication API is running'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'Route not found',
        message: `The requested route ${req.method} ${req.originalUrl} was not found` 
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: 'An unexpected error occurred' 
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`JWT Authentication API is running on port ${PORT}`);
    console.log(`Available endpoints:`);
    console.log(`   POST /register - Create a new user`);
    console.log(`   POST /login    - Authenticate and get JWT`);
    console.log(`   GET  /profile  - Get user profile (requires JWT)`);
    console.log(`   GET  /health   - Health check`);
    console.log(`\nJWT expires in: ${JWT_EXPIRES_IN}`);
    console.log(`User data stored in: ${USERS_FILE}`);
});

module.exports = app;