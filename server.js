const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Import routes
const authRoutes = require('./routes/auth');
const memberRoutes = require('./routes/members');
const eventRoutes = require('./routes/events');
const adminRoutes = require('./routes/admin');
const dashboardRoutes = require('./routes/dashboard');
const contactRoutes = require('./routes/contact');
const donationRoutes = require('./routes/donations');

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Stricter rate limiting for auth endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts, please try again later.'
});
app.use('/api/auth/', authLimiter);

// CORS configuration
app.use(cors({
    origin: process.env.NODE_ENV === 'production' 
        ? process.env.FRONTEND_URL 
        : ['http://localhost:3000', 'http://127.0.0.1:3000'],
    credentials: true
}));

// Compression middleware
app.use(compression());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// MongoDB connection
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/rtr2', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error('Database connection error:', error);
        process.exit(1);
    }
};

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'rotaract-club-secret-key-change-in-production',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI || 'mongodb://localhost:27017/rtr2',
        touchAfter: 24 * 3600 // lazy session update
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
}));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/members', memberRoutes);
app.use('/api/events', eventRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/contact', contactRoutes);
app.use('/api/donations', donationRoutes);
app.use('/dashboard', dashboardRoutes);

// Public routes (EJS templates)
app.get('/', (req, res) => {
    res.render('index', {
        title: 'Rotaract Club - Community Service & Leadership',
        user: req.session.user || null,
        currentPage: 'home'
    });
});

app.get('/about', (req, res) => {
    res.render('about', {
        title: 'About Us - Rotaract Club',
        user: req.session.user || null,
        currentPage: 'about'
    });
});

app.get('/events', (req, res) => {
    res.render('events', {
        title: 'Events - Rotaract Club',
        user: req.session.user || null,
        currentPage: 'events'
    });
});

app.get('/gallery', (req, res) => {
    res.render('gallery', {
        title: 'Gallery - Rotaract Club',
        user: req.session.user || null,
        currentPage: 'gallery'
    });
});

app.get('/contact', (req, res) => {
    res.render('contact', {
        title: 'Contact Us - Rotaract Club',
        user: req.session.user || null,
        currentPage: 'contact'
    });
});

app.get('/donate', (req, res) => {
    res.render('donate', {
        title: 'Make a Donation - Rotaract Club',
        user: req.session.user || null,
        currentPage: 'donate'
    });
});


// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    if (req.xhr || req.headers.accept.indexOf('json') > -1) {
        res.status(500).json({ 
            message: 'Something went wrong!',
            error: process.env.NODE_ENV === 'development' ? err.message : {}
        });
    } else {
        res.status(500).render('error', {
            title: 'Error - Rotaract Club',
            message: 'Something went wrong!',
            error: process.env.NODE_ENV === 'development' ? err : {}
        });
    }
});

// 404 handler
app.use((req, res) => {
    if (req.xhr || req.headers.accept?.includes('json')) {
        res.status(404).json({ message: 'Route not found' });
    } else {
        res.status(404).render('404', {
            title: 'Page Not Found - Rotaract Club',
            url: req.originalUrl
        });
    }
});


// Start server
const startServer = async () => {
    await connectDB();
    
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
        console.log(`🌐 Access the application at: http://localhost:${PORT}`);
    });
};

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received. Shutting down gracefully...');
    mongoose.connection.close();
    console.log('MongoDB connection closed.');
    process.exit(0);
});

startServer().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
});

module.exports = app;
