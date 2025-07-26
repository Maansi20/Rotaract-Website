const express = require('express');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const Contact = require('../models/Contact');
const { authenticateToken, authorizeRoles, optionalAuth } = require('../middleware/auth');

const router = express.Router();

// Rate limiting for contact form
const contactLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // limit each IP to 3 contact form submissions per windowMs
    message: { error: 'Too many contact form submissions, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Validation middleware
const contactValidation = [
    body('name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Name must be between 2 and 100 characters'),
    body('email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    body('phone')
        .optional()
        .isMobilePhone()
        .withMessage('Please provide a valid phone number'),
    body('subject')
        .trim()
        .isLength({ min: 5, max: 200 })
        .withMessage('Subject must be between 5 and 200 characters'),
    body('message')
        .trim()
        .isLength({ min: 10, max: 2000 })
        .withMessage('Message must be between 10 and 2000 characters'),
    body('category')
        .optional()
        .isIn(['general', 'membership', 'events', 'volunteering', 'donations', 'partnerships', 'media', 'complaints', 'suggestions', 'other'])
        .withMessage('Invalid category')
];

// @route   POST /api/contact
// @desc    Submit contact form
// @access  Public
router.post('/', contactLimiter, contactValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const { name, email, phone, subject, message, category } = req.body;

        // Check for potential duplicates (same email and subject within last hour)
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const existingContact = await Contact.findOne({
            email: email.toLowerCase(),
            subject: subject,
            createdAt: { $gte: oneHourAgo }
        });

        if (existingContact) {
            return res.status(429).json({
                success: false,
                message: 'A similar message was already submitted recently. Please wait before submitting again.'
            });
        }

        // Create new contact entry
        const contact = new Contact({
            name,
            email,
            phone,
            subject,
            message,
            category: category || 'general',
            metadata: {
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                referrer: req.get('Referer')
            }
        });

        await contact.save();

        // Send auto-response email (in production)
        try {
            await contact.sendAutoResponse();
        } catch (error) {
            console.error('Auto-response failed:', error);
            // Don't fail the request if auto-response fails
        }

        res.status(201).json({
            success: true,
            message: 'Thank you for your message! We will get back to you soon.',
            data: {
                id: contact._id,
                status: contact.status,
                category: contact.category
            }
        });

    } catch (error) {
        console.error('Contact form submission error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to submit your message. Please try again.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/contact
// @desc    Get all contact messages (admin/BOD only)
// @access  Private (Admin/BOD)
router.get('/', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            status,
            category,
            priority,
            assignedTo,
            search,
            sortBy = 'createdAt',
            sortOrder = 'desc'
        } = req.query;

        // Build query
        const query = {};
        
        if (status) query.status = status;
        if (category) query.category = category;
        if (priority) query.priority = priority;
        if (assignedTo) query.assignedTo = assignedTo;
        
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { subject: { $regex: search, $options: 'i' } },
                { message: { $regex: search, $options: 'i' } }
            ];
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const sort = { [sortBy]: sortOrder === 'desc' ? -1 : 1 };

        // Execute query
        const [contacts, total] = await Promise.all([
            Contact.find(query)
                .populate('assignedTo', 'firstName lastName email')
                .populate('responses.respondedBy', 'firstName lastName email')
                .sort(sort)
                .skip(skip)
                .limit(parseInt(limit)),
            Contact.countDocuments(query)
        ]);

        res.json({
            success: true,
            data: {
                contacts,
                pagination: {
                    currentPage: parseInt(page),
                    totalPages: Math.ceil(total / parseInt(limit)),
                    totalItems: total,
                    itemsPerPage: parseInt(limit)
                }
            }
        });

    } catch (error) {
        console.error('Get contacts error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contact messages',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/contact/:id
// @desc    Get specific contact message
// @access  Private (Admin/BOD)
router.get('/:id', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const contact = await Contact.findById(req.params.id)
            .populate('assignedTo', 'firstName lastName email profileImage')
            .populate('responses.respondedBy', 'firstName lastName email profileImage')
            .populate('followUps.assignedTo', 'firstName lastName email')
            .populate('followUps.completedBy', 'firstName lastName email')
            .populate('internalNotes.addedBy', 'firstName lastName email');

        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact message not found'
            });
        }

        res.json({
            success: true,
            data: { contact }
        });

    } catch (error) {
        console.error('Get contact error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contact message',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/contact/:id/assign
// @desc    Assign contact to user
// @access  Private (Admin/BOD)
router.put('/:id/assign', authenticateToken, authorizeRoles('admin', 'bod'), [
    body('assignedTo').isMongoId().withMessage('Invalid user ID')
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

        const { assignedTo } = req.body;

        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact message not found'
            });
        }

        await contact.assignTo(assignedTo);

        res.json({
            success: true,
            message: 'Contact message assigned successfully',
            data: { contact }
        });

    } catch (error) {
        console.error('Assign contact error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to assign contact message',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/contact/:id/respond
// @desc    Add response to contact message
// @access  Private (Admin/BOD/Core)
router.post('/:id/respond', authenticateToken, authorizeRoles('admin', 'bod', 'core'), [
    body('message')
        .trim()
        .isLength({ min: 10, max: 2000 })
        .withMessage('Response must be between 10 and 2000 characters'),
    body('method')
        .optional()
        .isIn(['email', 'phone', 'in-person', 'other'])
        .withMessage('Invalid response method'),
    body('isPublic')
        .optional()
        .isBoolean()
        .withMessage('isPublic must be a boolean')
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

        const { message, method = 'email', isPublic = false } = req.body;

        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact message not found'
            });
        }

        await contact.addResponse(req.user.id, message, method, isPublic);

        res.json({
            success: true,
            message: 'Response added successfully',
            data: { contact }
        });

    } catch (error) {
        console.error('Add response error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add response',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/contact/:id/note
// @desc    Add internal note to contact message
// @access  Private (Admin/BOD/Core)
router.post('/:id/note', authenticateToken, authorizeRoles('admin', 'bod', 'core'), [
    body('note')
        .trim()
        .isLength({ min: 5, max: 1000 })
        .withMessage('Note must be between 5 and 1000 characters'),
    body('isImportant')
        .optional()
        .isBoolean()
        .withMessage('isImportant must be a boolean')
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

        const { note, isImportant = false } = req.body;

        const contact = await Contact.findById(req.params.id);
        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact message not found'
            });
        }

        await contact.addInternalNote(req.user.id, note, isImportant);

        res.json({
            success: true,
            message: 'Internal note added successfully',
            data: { contact }
        });

    } catch (error) {
        console.error('Add note error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to add internal note',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/contact/:id/status
// @desc    Update contact status
// @access  Private (Admin/BOD/Core)
router.put('/:id/status', authenticateToken, authorizeRoles('admin', 'bod', 'core'), [
    body('status')
        .isIn(['new', 'in-progress', 'resolved', 'closed', 'spam'])
        .withMessage('Invalid status')
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

        const { status } = req.body;

        const contact = await Contact.findByIdAndUpdate(
            req.params.id,
            { status },
            { new: true, runValidators: true }
        );

        if (!contact) {
            return res.status(404).json({
                success: false,
                message: 'Contact message not found'
            });
        }

        res.json({
            success: true,
            message: 'Status updated successfully',
            data: { contact }
        });

    } catch (error) {
        console.error('Update status error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update status',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/contact/stats
// @desc    Get contact statistics
// @access  Private (Admin/BOD)
router.get('/admin/stats', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const { startDate, endDate } = req.query;

        const stats = await Contact.getStats(startDate, endDate);

        // Get additional metrics
        const overdue = await Contact.findOverdue();
        const pendingFollowUps = await Contact.findPendingFollowUps();

        res.json({
            success: true,
            data: {
                ...stats,
                overdueCount: overdue.length,
                pendingFollowUpsCount: pendingFollowUps.length
            }
        });

    } catch (error) {
        console.error('Get contact stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch contact statistics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/contact/overdue
// @desc    Get overdue contact messages
// @access  Private (Admin/BOD)
router.get('/admin/overdue', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const overdueContacts = await Contact.findOverdue()
            .populate('assignedTo', 'firstName lastName email')
            .sort({ createdAt: 1 });

        res.json({
            success: true,
            data: { contacts: overdueContacts }
        });

    } catch (error) {
        console.error('Get overdue contacts error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch overdue contacts',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

module.exports = router;
