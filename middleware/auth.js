const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Middleware to authenticate JWT token
const authenticateToken = async (req, res, next) => {
    try {
        let token;

        // Check for token in Authorization header
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }
        // Check for token in cookies
        else if (req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Access denied. No token provided.'
            });
        }

        // Verify token
        const decoded = jwt.verify(
            token, 
            process.env.JWT_SECRET || 'rotaract-jwt-secret-change-in-production'
        );

        // Check if user still exists and is active
        const user = await User.findById(decoded.id);
        
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Token is invalid. User no longer exists.'
            });
        }

        if (user.status !== 'active') {
            return res.status(403).json({
                success: false,
                message: 'Your account is not active. Please contact support.'
            });
        }

        // Check if user changed password after token was issued
        const tokenIssuedAt = new Date(decoded.iat * 1000);
        if (user.updatedAt > tokenIssuedAt) {
            return res.status(401).json({
                success: false,
                message: 'Token is invalid. Please log in again.'
            });
        }

        // Add user to request object
        req.user = {
            id: user._id,
            email: user.email,
            role: user.role,
            status: user.status,
            firstName: user.firstName,
            lastName: user.lastName
        };

        next();

    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token.'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token has expired. Please log in again.'
            });
        }

        console.error('Authentication error:', error);
        return res.status(500).json({
            success: false,
            message: 'Authentication failed.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Middleware to authorize specific roles
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Insufficient permissions.'
            });
        }

        next();
    };
};

// Middleware to check if user owns resource or has admin privileges
const authorizeOwnerOrAdmin = (resourceUserField = 'user') => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.'
                });
            }

            // Admin and BOD can access any resource
            if (['admin', 'bod'].includes(req.user.role)) {
                return next();
            }

            // For other roles, check ownership
            const resourceId = req.params.id;
            if (!resourceId) {
                return res.status(400).json({
                    success: false,
                    message: 'Resource ID is required.'
                });
            }

            // This is a generic check - in practice, you'd check against specific models
            // For now, we'll allow the request to proceed and let the route handler
            // perform the specific ownership check
            next();

        } catch (error) {
            console.error('Authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed.',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    };
};

// Middleware to check if user can access specific user data
const authorizeUserAccess = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        const targetUserId = req.params.userId || req.params.id;
        
        // Admin and BOD can access any user data
        if (['admin', 'bod'].includes(req.user.role)) {
            return next();
        }

        // Core team can access member data
        if (req.user.role === 'core') {
            const targetUser = await User.findById(targetUserId);
            if (targetUser && targetUser.role === 'member') {
                return next();
            }
        }

        // Users can only access their own data
        if (req.user.id === targetUserId) {
            return next();
        }

        return res.status(403).json({
            success: false,
            message: 'Access denied. You can only access your own data.'
        });

    } catch (error) {
        console.error('User access authorization error:', error);
        return res.status(500).json({
            success: false,
            message: 'Authorization failed.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
};

// Middleware to check if user can perform action based on event visibility
const authorizeEventAccess = (action = 'view') => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                // For public events, allow unauthenticated access for viewing
                if (action === 'view') {
                    return next();
                }
                
                return res.status(401).json({
                    success: false,
                    message: 'Authentication required.'
                });
            }

            // Admin and BOD have full access
            if (['admin', 'bod'].includes(req.user.role)) {
                return next();
            }

            // For other actions, let the route handler check specific permissions
            next();

        } catch (error) {
            console.error('Event access authorization error:', error);
            return res.status(500).json({
                success: false,
                message: 'Authorization failed.',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    };
};

// Middleware to log user activity
const logActivity = (action) => {
    return async (req, res, next) => {
        try {
            if (req.user) {
                // In a production app, you might want to log this to a separate collection
                console.log(`User ${req.user.email} performed action: ${action} at ${new Date().toISOString()}`);
                
                // You could also update user's last activity timestamp
                await User.findByIdAndUpdate(req.user.id, {
                    lastActivity: new Date()
                }, { validateBeforeSave: false });
            }
            
            next();
        } catch (error) {
            // Don't fail the request if logging fails
            console.error('Activity logging error:', error);
            next();
        }
    };
};

// Middleware to check if user has specific permissions
const checkPermission = (permission) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required.'
            });
        }

        // Define role-based permissions
        const rolePermissions = {
            admin: [
                'manage_users', 'manage_events', 'manage_donations', 
                'manage_announcements', 'view_analytics', 'manage_settings'
            ],
            bod: [
                'manage_members', 'approve_events', 'view_donations',
                'create_announcements', 'view_reports', 'manage_events'
            ],
            core: [
                'manage_event_logistics', 'update_event_status', 
                'manage_media', 'view_member_list'
            ],
            member: [
                'view_events', 'register_events', 'update_profile',
                'view_announcements', 'participate_discussions'
            ]
        };

        const userPermissions = rolePermissions[req.user.role] || [];
        
        if (!userPermissions.includes(permission)) {
            return res.status(403).json({
                success: false,
                message: `Access denied. Required permission: ${permission}`
            });
        }

        next();
    };
};

// Middleware to validate session
const validateSession = (req, res, next) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({
            success: false,
            message: 'Session expired. Please log in again.'
        });
    }

    // Check if session user matches JWT user (if both exist)
    if (req.user && req.session.user.id !== req.user.id) {
        return res.status(401).json({
            success: false,
            message: 'Session mismatch. Please log in again.'
        });
    }

    next();
};

// Optional authentication - doesn't fail if no token provided
const optionalAuth = async (req, res, next) => {
    try {
        let token;

        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        } else if (req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        if (token) {
            try {
                const decoded = jwt.verify(
                    token, 
                    process.env.JWT_SECRET || 'rotaract-jwt-secret-change-in-production'
                );

                const user = await User.findById(decoded.id);
                
                if (user && user.status === 'active') {
                    req.user = {
                        id: user._id,
                        email: user.email,
                        role: user.role,
                        status: user.status,
                        firstName: user.firstName,
                        lastName: user.lastName
                    };
                }
            } catch (error) {
                // Token is invalid, but we don't fail the request
                console.log('Optional auth failed:', error.message);
            }
        }

        next();
    } catch (error) {
        console.error('Optional authentication error:', error);
        next();
    }
};

module.exports = {
    authenticateToken,
    authorizeRoles,
    authorizeOwnerOrAdmin,
    authorizeUserAccess,
    authorizeEventAccess,
    logActivity,
    checkPermission,
    validateSession,
    optionalAuth
};
