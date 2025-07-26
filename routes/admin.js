const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Event = require('../models/Event');
const Donation = require('../models/Donation');
const Announcement = require('../models/Announcement');
const Contact = require('../models/Contact');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

// All admin routes require authentication and admin/BOD role
router.use(authenticateToken);
router.use(authorizeRoles('admin', 'bod'));

// @route   GET /api/admin/dashboard
// @desc    Get admin dashboard data
// @access  Private (Admin/BOD)
router.get('/dashboard', async (req, res) => {
    try {
        const [userStats, eventStats, donationStats, contactStats] = await Promise.all([
            User.getStats(),
            Event.getStats(),
            Donation.getStats(),
            Contact.getStats()
        ]);

        // Get recent activity
        const recentActivity = {
            newMembers: await User.find({ status: 'active' })
                .sort({ createdAt: -1 })
                .limit(5)
                .select('firstName lastName email createdAt'),
            recentEvents: await Event.find({ status: 'published' })
                .populate('organizer', 'firstName lastName')
                .sort({ createdAt: -1 })
                .limit(5),
            recentDonations: await Donation.find({ status: 'completed' })
                .sort({ createdAt: -1 })
                .limit(5),
            pendingContacts: await Contact.find({ status: 'new' })
                .sort({ createdAt: -1 })
                .limit(5)
        };

        // Get alerts and notifications
        const alerts = {
            pendingApplications: await User.countDocuments({ status: 'pending' }),
            overdueContacts: (await Contact.findOverdue()).length,
            upcomingEvents: await Event.countDocuments({
                status: 'published',
                startDate: { 
                    $gte: new Date(),
                    $lte: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // Next 7 days
                }
            }),
            lowAttendanceEvents: await Event.find({
                status: 'published',
                startDate: { $gt: new Date() },
                maxParticipants: { $ne: null }
            }).then(events => events.filter(e => e.currentParticipants < e.maxParticipants * 0.3).length)
        };

        res.json({
            success: true,
            data: {
                stats: {
                    users: userStats,
                    events: eventStats,
                    donations: donationStats,
                    contacts: contactStats
                },
                recentActivity,
                alerts
            }
        });

    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard data',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/admin/users
// @desc    Get all users with advanced filtering
// @access  Private (Admin/BOD)
router.get('/users', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            role,
            status,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc',
            dateFrom,
            dateTo
        } = req.query;

        // Build query
        const query = {};
        
        if (role) query.role = role;
        if (status) query.status = status;
        
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        if (dateFrom || dateTo) {
            query.createdAt = {};
            if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
            if (dateTo) query.createdAt.$lte = new Date(dateTo);
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [users, total] = await Promise.all([
            User.find(query)
                .select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            User.countDocuments(query)
        ]);

        res.json({
            success: true,
            data: {
                users,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch users',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/admin/users
// @desc    Create new user
// @access  Private (Admin)
router.post('/users', authorizeRoles('admin'), [
    body('firstName').trim().isLength({ min: 2, max: 50 }).withMessage('First name must be between 2 and 50 characters'),
    body('lastName').trim().isLength({ min: 2, max: 50 }).withMessage('Last name must be between 2 and 50 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email address'),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long'),
    body('phone').isMobilePhone().withMessage('Please provide a valid phone number'),
    body('role').isIn(['member', 'core', 'bod', 'admin']).withMessage('Invalid role'),
    body('status').optional().isIn(['pending', 'active', 'inactive', 'suspended']).withMessage('Invalid status')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { firstName, lastName, email, password, phone, role, status = 'active' } = req.body;

        // Check if user already exists
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        const user = new User({
            firstName,
            lastName,
            email,
            password,
            phone,
            role,
            status,
            isEmailVerified: true, // Admin-created users are pre-verified
            metadata: {
                createdBy: req.user.id,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent')
            }
        });

        await user.save();

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: {
                user: {
                    id: user._id,
                    firstName: user.firstName,
                    lastName: user.lastName,
                    email: user.email,
                    role: user.role,
                    status: user.status
                }
            }
        });

    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/admin/users/:id
// @desc    Update user
// @access  Private (Admin)
router.put('/users/:id', authorizeRoles('admin'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent admin from changing their own role
        if (user._id.toString() === req.user.id && req.body.role && req.body.role !== user.role) {
            return res.status(403).json({
                success: false,
                message: 'Cannot change your own role'
            });
        }

        const updateData = { ...req.body };
        updateData.metadata = { ...user.metadata, updatedBy: req.user.id };

        // Remove sensitive fields that shouldn't be updated via this endpoint
        delete updateData.password;
        delete updateData.passwordResetToken;
        delete updateData.emailVerificationToken;

        const updatedUser = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret');

        res.json({
            success: true,
            message: 'User updated successfully',
            data: { user: updatedUser }
        });

    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   DELETE /api/admin/users/:id
// @desc    Delete user
// @access  Private (Admin)
router.delete('/users/:id', authorizeRoles('admin'), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Prevent admin from deleting themselves
        if (user._id.toString() === req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Cannot delete your own account'
            });
        }

        // Prevent deletion of other admin users (unless super admin)
        if (user.role === 'admin' && req.user.role !== 'super-admin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot delete admin users'
            });
        }

        await User.findByIdAndDelete(req.params.id);

        res.json({
            success: true,
            message: 'User deleted successfully'
        });

    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/admin/events
// @desc    Get all events for admin management
// @access  Private (Admin/BOD)
router.get('/events', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            status,
            category,
            type,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Build query
        const query = {};
        
        if (status) query.status = status;
        if (category) query.category = category;
        if (type) query.type = type;
        
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { 'location.name': { $regex: search, $options: 'i' } }
            ];
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [events, total] = await Promise.all([
            Event.find(query)
                .populate('organizer', 'firstName lastName email')
                .populate('coOrganizers', 'firstName lastName email')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            Event.countDocuments(query)
        ]);

        res.json({
            success: true,
            data: {
                events,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get admin events error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch events',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/admin/events/:id/approve
// @desc    Approve event
// @access  Private (Admin/BOD)
router.put('/events/:id/approve', async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        
        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        event.status = 'published';
        event.metadata.approvedBy = req.user.id;
        event.metadata.approvedAt = new Date();
        
        await event.save();

        res.json({
            success: true,
            message: 'Event approved successfully',
            data: { event }
        });

    } catch (error) {
        console.error('Approve event error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to approve event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/admin/donations
// @desc    Get all donations
// @access  Private (Admin/BOD)
router.get('/donations', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            status,
            type,
            category,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc',
            dateFrom,
            dateTo
        } = req.query;

        // Build query
        const query = {};
        
        if (status) query.status = status;
        if (type) query.type = type;
        if (category) query.category = category;
        
        if (search) {
            query.$or = [
                { 'donor.name': { $regex: search, $options: 'i' } },
                { 'donor.email': { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }

        if (dateFrom || dateTo) {
            query.createdAt = {};
            if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
            if (dateTo) query.createdAt.$lte = new Date(dateTo);
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [donations, total] = await Promise.all([
            Donation.find(query)
                .populate('campaign', 'title')
                .populate('event', 'title')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            Donation.countDocuments(query)
        ]);

        res.json({
            success: true,
            data: {
                donations,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get donations error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch donations',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/admin/announcements
// @desc    Get all announcements
// @access  Private (Admin/BOD)
router.get('/announcements', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            status,
            type,
            priority,
            visibility,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Build query
        const query = {};
        
        if (status) query.status = status;
        if (type) query.type = type;
        if (priority) query.priority = priority;
        if (visibility) query.visibility = visibility;
        
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { content: { $regex: search, $options: 'i' } },
                { summary: { $regex: search, $options: 'i' } }
            ];
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [announcements, total] = await Promise.all([
            Announcement.find(query)
                .populate('author', 'firstName lastName email')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            Announcement.countDocuments(query)
        ]);

        res.json({
            success: true,
            data: {
                announcements,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get announcements error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch announcements',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/admin/announcements
// @desc    Create new announcement
// @access  Private (Admin/BOD)
router.post('/announcements', [
    body('title').trim().isLength({ min: 5, max: 100 }).withMessage('Title must be between 5 and 100 characters'),
    body('content').trim().isLength({ min: 20, max: 5000 }).withMessage('Content must be between 20 and 5000 characters'),
    body('type').isIn(['general', 'urgent', 'event', 'meeting', 'deadline', 'celebration', 'policy', 'other']).withMessage('Invalid type'),
    body('priority').optional().isIn(['low', 'normal', 'high', 'urgent']).withMessage('Invalid priority'),
    body('visibility').isIn(['public', 'members', 'bod', 'core', 'admin']).withMessage('Invalid visibility')
], async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const announcementData = {
            ...req.body,
            author: req.user.id,
            metadata: {
                createdBy: req.user.id
            }
        };

        const announcement = new Announcement(announcementData);
        await announcement.save();

        await announcement.populate('author', 'firstName lastName email');

        res.status(201).json({
            success: true,
            message: 'Announcement created successfully',
            data: { announcement }
        });

    } catch (error) {
        console.error('Create announcement error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create announcement',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/admin/reports
// @desc    Get comprehensive reports
// @access  Private (Admin/BOD)
router.get('/reports', async (req, res) => {
    try {
        const { type = 'overview', startDate, endDate } = req.query;

        let reportData = {};

        switch (type) {
            case 'overview':
                reportData = {
                    users: await User.getStats(),
                    events: await Event.getStats(),
                    donations: await Donation.getStats(startDate, endDate),
                    contacts: await Contact.getStats(startDate, endDate)
                };
                break;

            case 'members':
                reportData = await User.getStats();
                reportData.growthData = await User.aggregate([
                    {
                        $match: startDate && endDate ? {
                            createdAt: { $gte: new Date(startDate), $lte: new Date(endDate) }
                        } : {}
                    },
                    {
                        $group: {
                            _id: {
                                year: { $year: '$createdAt' },
                                month: { $month: '$createdAt' }
                            },
                            count: { $sum: 1 }
                        }
                    },
                    { $sort: { '_id.year': 1, '_id.month': 1 } }
                ]);
                break;

            case 'events':
                reportData = await Event.getStats();
                break;

            case 'donations':
                reportData = await Donation.getStats(startDate, endDate);
                reportData.topDonors = await Donation.getTopDonors(10);
                break;

            case 'contacts':
                reportData = await Contact.getStats(startDate, endDate);
                break;

            default:
                return res.status(400).json({
                    success: false,
                    message: 'Invalid report type'
                });
        }

        res.json({
            success: true,
            data: {
                type,
                period: { startDate, endDate },
                generatedAt: new Date(),
                ...reportData
            }
        });

    } catch (error) {
        console.error('Generate report error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to generate report',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

module.exports = router;
