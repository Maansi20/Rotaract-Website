const express = require('express');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const User = require('../models/User');
const { authenticateToken, authorizeRoles, authorizeUserAccess } = require('../middleware/auth');

const router = express.Router();

// Configure multer for profile image uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/profiles/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'profile-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

// Validation middleware
const memberApplicationValidation = [
    body('firstName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters'),
    body('lastName')
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    body('phone')
        .isMobilePhone()
        .withMessage('Please provide a valid phone number'),
    body('interests')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Interests cannot exceed 500 characters')
];

const profileUpdateValidation = [
    body('firstName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('First name must be between 2 and 50 characters'),
    body('lastName')
        .optional()
        .trim()
        .isLength({ min: 2, max: 50 })
        .withMessage('Last name must be between 2 and 50 characters'),
    body('phone')
        .optional()
        .isMobilePhone()
        .withMessage('Please provide a valid phone number'),
    body('interests')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Interests cannot exceed 500 characters'),
    body('skills')
        .optional()
        .isArray()
        .withMessage('Skills must be an array'),
    body('skills.*')
        .optional()
        .trim()
        .isLength({ min: 1, max: 50 })
        .withMessage('Each skill must be between 1 and 50 characters')
];

// @route   POST /api/members/apply
// @desc    Submit membership application
// @access  Public
router.post('/apply', memberApplicationValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { firstName, lastName, email, phone, interests } = req.body;

        // Check if user already exists
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: 'An application with this email already exists'
            });
        }

        // Create new member application
        const user = new User({
            firstName,
            lastName,
            email,
            phone,
            interests,
            role: 'member',
            status: 'pending',
            // Temporary password - user will need to set password after approval
            password: Math.random().toString(36).slice(-8) + 'Temp1!',
            metadata: {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent')
            }
        });

        await user.save();

        // Generate email verification token
        const verificationToken = user.createEmailVerificationToken();
        await user.save({ validateBeforeSave: false });

        // In production, send notification email to admins and confirmation to applicant
        // await sendApplicationNotification(user);
        // await sendApplicationConfirmation(user.email, verificationToken);

        res.status(201).json({
            success: true,
            message: 'Application submitted successfully! We will review your application and contact you soon.',
            data: {
                id: user._id,
                email: user.email,
                status: user.status
            }
        });

    } catch (error) {
        console.error('Member application error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit application. Please try again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/members
// @desc    Get all members (filtered by role permissions)
// @access  Private
router.get('/', authenticateToken, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            role,
            status,
            search,
            sortBy = 'joinDate',
            sortOrder = 'desc'
        } = req.query;

        // Build query based on user permissions
        const query = {};
        
        // Role-based filtering
        if (req.user.role === 'member') {
            // Members can only see active members
            query.status = 'active';
            query.role = 'member';
        } else if (req.user.role === 'core') {
            // Core team can see all members
            query.role = { $in: ['member'] };
        } else if (req.user.role === 'bod') {
            // BOD can see members and core team
            query.role = { $in: ['member', 'core'] };
        }
        // Admin can see all users (no additional filtering)

        // Apply additional filters
        if (role && ['admin', 'bod'].includes(req.user.role)) {
            query.role = role;
        }
        if (status && ['admin', 'bod'].includes(req.user.role)) {
            query.status = status;
        }
        
        if (search) {
            query.$or = [
                { firstName: { $regex: search, $options: 'i' } },
                { lastName: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ];
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [members, total] = await Promise.all([
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
                members,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get members error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch members',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/members/:id
// @desc    Get single member profile
// @access  Private
router.get('/:id', authenticateToken, authorizeUserAccess, async (req, res) => {
    try {
        const member = await User.findById(req.params.id)
            .select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret');

        if (!member) {
            return res.status(404).json({
                success: false,
                message: 'Member not found'
            });
        }

        res.json({
            success: true,
            data: { member }
        });

    } catch (error) {
        console.error('Get member error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch member profile',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/members/:id
// @desc    Update member profile
// @access  Private
router.put('/:id', authenticateToken, authorizeUserAccess, upload.single('profileImage'), profileUpdateValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const member = await User.findById(req.params.id);
        
        if (!member) {
            return res.status(404).json({
                success: false,
                message: 'Member not found'
            });
        }

        // Prepare update data
        const updateData = { ...req.body };
        updateData.metadata = { ...member.metadata, updatedBy: req.user.id };

        // Handle profile image upload
        if (req.file) {
            updateData.profileImage = `/uploads/profiles/${req.file.filename}`;
        }

        // Parse JSON fields if they're strings
        ['address', 'socialMedia', 'preferences'].forEach(field => {
            if (req.body[field] && typeof req.body[field] === 'string') {
                try {
                    updateData[field] = JSON.parse(req.body[field]);
                } catch (e) {
                    // Keep original value if parsing fails
                }
            }
        });

        // Only admin/BOD can change role and status
        if (!['admin', 'bod'].includes(req.user.role)) {
            delete updateData.role;
            delete updateData.status;
        }

        const updatedMember = await User.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret');

        res.json({
            success: true,
            message: 'Profile updated successfully',
            data: { member: updatedMember }
        });

    } catch (error) {
        console.error('Update member error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update profile',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/members/:id/status
// @desc    Update member status (approve/reject/suspend)
// @access  Private (Admin/BOD)
router.put('/:id/status', authenticateToken, authorizeRoles('admin', 'bod'), [
    body('status')
        .isIn(['pending', 'active', 'inactive', 'suspended'])
        .withMessage('Invalid status'),
    body('reason')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Reason cannot exceed 500 characters')
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

        const { status, reason } = req.body;

        const member = await User.findById(req.params.id);
        
        if (!member) {
            return res.status(404).json({
                success: false,
                message: 'Member not found'
            });
        }

        const oldStatus = member.status;
        member.status = status;
        member.metadata.updatedBy = req.user.id;

        // Add internal note about status change
        if (reason) {
            // In a real app, you might have a separate notes/history collection
            console.log(`Status changed from ${oldStatus} to ${status} by ${req.user.email}. Reason: ${reason}`);
        }

        await member.save({ validateBeforeSave: false });

        // Send notification email based on status change
        // if (status === 'active' && oldStatus === 'pending') {
        //     await sendApprovalEmail(member.email);
        // } else if (status === 'suspended') {
        //     await sendSuspensionEmail(member.email, reason);
        // }

        res.json({
            success: true,
            message: `Member status updated to ${status}`,
            data: { 
                member: {
                    id: member._id,
                    firstName: member.firstName,
                    lastName: member.lastName,
                    email: member.email,
                    status: member.status
                }
            }
        });

    } catch (error) {
        console.error('Update member status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update member status',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/members/:id/role
// @desc    Update member role
// @access  Private (Admin only)
router.put('/:id/role', authenticateToken, authorizeRoles('admin'), [
    body('role')
        .isIn(['member', 'core', 'bod', 'admin'])
        .withMessage('Invalid role'),
    body('reason')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Reason cannot exceed 500 characters')
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

        const { role, reason } = req.body;

        const member = await User.findById(req.params.id);
        
        if (!member) {
            return res.status(404).json({
                success: false,
                message: 'Member not found'
            });
        }

        const oldRole = member.role;
        member.role = role;
        member.metadata.updatedBy = req.user.id;

        await member.save({ validateBeforeSave: false });

        // Log role change
        console.log(`Role changed from ${oldRole} to ${role} for ${member.email} by ${req.user.email}. Reason: ${reason || 'No reason provided'}`);

        res.json({
            success: true,
            message: `Member role updated to ${role}`,
            data: { 
                member: {
                    id: member._id,
                    firstName: member.firstName,
                    lastName: member.lastName,
                    email: member.email,
                    role: member.role
                }
            }
        });

    } catch (error) {
        console.error('Update member role error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update member role',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   DELETE /api/members/:id
// @desc    Delete member (Admin only)
// @access  Private (Admin)
router.delete('/:id', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const member = await User.findById(req.params.id);
        
        if (!member) {
            return res.status(404).json({
                success: false,
                message: 'Member not found'
            });
        }

        // Prevent deletion of admin users
        if (member.role === 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Cannot delete admin users'
            });
        }

        // In production, you might want to soft delete or archive instead
        await User.findByIdAndDelete(req.params.id);

        res.json({
            success: true,
            message: 'Member deleted successfully'
        });

    } catch (error) {
        console.error('Delete member error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete member',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/members/pending/applications
// @desc    Get pending member applications
// @access  Private (Admin/BOD)
router.get('/admin/pending', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;

        const skip = (parseInt(page) - 1) * parseInt(limit);

        const [applications, total] = await Promise.all([
            User.find({ status: 'pending' })
                .select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret')
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(parseInt(limit)),
            User.countDocuments({ status: 'pending' })
        ]);

        res.json({
            success: true,
            data: {
                applications,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get pending applications error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch pending applications',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/members/stats
// @desc    Get member statistics
// @access  Private (Admin/BOD)
router.get('/admin/stats', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const stats = await User.getStats();

        // Get additional metrics
        const recentJoins = await User.find({
            joinDate: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) }, // Last 30 days
            status: 'active'
        }).countDocuments();

        const pendingApplications = await User.countDocuments({ status: 'pending' });

        res.json({
            success: true,
            data: {
                ...stats,
                recentJoins,
                pendingApplications
            }
        });

    } catch (error) {
        console.error('Get member stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch member statistics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

module.exports = router;
