const express = require('express');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const path = require('path');
const Event = require('../models/Event');
const { authenticateToken, authorizeRoles, optionalAuth, checkPermission } = require('../middleware/auth');

const router = express.Router();

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/events/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        if (file.fieldname === 'images') {
            // Allow only image files
            if (file.mimetype.startsWith('image/')) {
                cb(null, true);
            } else {
                cb(new Error('Only image files are allowed for images'), false);
            }
        } else if (file.fieldname === 'documents') {
            // Allow documents
            const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
            if (allowedTypes.includes(file.mimetype)) {
                cb(null, true);
            } else {
                cb(new Error('Only PDF and Word documents are allowed'), false);
            }
        } else {
            cb(new Error('Invalid field name'), false);
        }
    }
});

// Validation middleware
const eventValidation = [
    body('title')
        .trim()
        .isLength({ min: 5, max: 100 })
        .withMessage('Title must be between 5 and 100 characters'),
    body('description')
        .trim()
        .isLength({ min: 20, max: 2000 })
        .withMessage('Description must be between 20 and 2000 characters'),
    body('category')
        .isIn(['community-service', 'fundraising', 'social', 'professional-development', 'environmental', 'health', 'education', 'other'])
        .withMessage('Invalid category'),
    body('startDate')
        .isISO8601()
        .withMessage('Invalid start date format'),
    body('endDate')
        .isISO8601()
        .withMessage('Invalid end date format')
        .custom((value, { req }) => {
            if (new Date(value) <= new Date(req.body.startDate)) {
                throw new Error('End date must be after start date');
            }
            return true;
        }),
    body('location.name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Location name must be between 2 and 100 characters'),
    body('maxParticipants')
        .optional()
        .isInt({ min: 1 })
        .withMessage('Maximum participants must be a positive integer'),
    body('registrationFee.amount')
        .optional()
        .isFloat({ min: 0 })
        .withMessage('Registration fee must be a non-negative number')
];

// @route   GET /api/events
// @desc    Get all events (public and filtered by user role)
// @access  Public/Private
router.get('/', optionalAuth, async (req, res) => {
    try {
        const {
            page = 1,
            limit = 12,
            category,
            type,
            status = 'published',
            upcoming = false,
            search,
            sortBy = 'startDate',
            sortOrder = 'asc'
        } = req.query;

        // Build query based on user role and filters
        const query = { status };
        
        // Filter by user role and event type
        if (!req.user) {
            // Public access - only public events
            query.type = 'public';
        } else {
            // Authenticated users can see events based on their role
            const allowedTypes = ['public'];
            if (req.user.role === 'member') allowedTypes.push('members-only');
            if (req.user.role === 'core') allowedTypes.push('members-only', 'core-only');
            if (['bod', 'admin'].includes(req.user.role)) allowedTypes.push('members-only', 'core-only', 'bod-only');
            
            query.type = { $in: allowedTypes };
        }

        if (category) query.category = category;
        if (type && req.user) query.type = type; // Override type filter if user is authenticated
        
        if (upcoming === 'true') {
            query.startDate = { $gt: new Date() };
        }
        
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
                .populate('organizer', 'firstName lastName email profileImage')
                .populate('coOrganizers', 'firstName lastName email profileImage')
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
        console.error('Get events error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch events',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/events/upcoming
// @desc    Get upcoming events
// @access  Public
router.get('/upcoming', optionalAuth, async (req, res) => {
    try {
        const { limit = 6 } = req.query;

        const query = {
            status: 'published',
            startDate: { $gt: new Date() }
        };

        // Filter by user role
        if (!req.user) {
            query.type = 'public';
        } else {
            const allowedTypes = ['public'];
            if (req.user.role === 'member') allowedTypes.push('members-only');
            if (req.user.role === 'core') allowedTypes.push('members-only', 'core-only');
            if (['bod', 'admin'].includes(req.user.role)) allowedTypes.push('members-only', 'core-only', 'bod-only');
            
            query.type = { $in: allowedTypes };
        }

        const events = await Event.find(query)
            .populate('organizer', 'firstName lastName email')
            .sort({ startDate: 1 })
            .limit(parseInt(limit));

        res.json({
            success: true,
            data: { events }
        });

    } catch (error) {
        console.error('Get upcoming events error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch upcoming events',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/events/:id
// @desc    Get single event
// @access  Public/Private
router.get('/:id', optionalAuth, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id)
            .populate('organizer', 'firstName lastName email profileImage')
            .populate('coOrganizers', 'firstName lastName email profileImage')
            .populate('participants.user', 'firstName lastName email profileImage')
            .populate('feedback.user', 'firstName lastName email profileImage');

        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        // Check if user can view this event
        if (event.type !== 'public' && !req.user) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required to view this event'
            });
        }

        if (req.user) {
            const allowedTypes = ['public'];
            if (req.user.role === 'member') allowedTypes.push('members-only');
            if (req.user.role === 'core') allowedTypes.push('members-only', 'core-only');
            if (['bod', 'admin'].includes(req.user.role)) allowedTypes.push('members-only', 'core-only', 'bod-only');
            
            if (!allowedTypes.includes(event.type)) {
                return res.status(403).json({
                    success: false,
                    message: 'You do not have permission to view this event'
                });
            }
        }

        // Increment view count
        event.analytics.views += 1;
        await event.save({ validateBeforeSave: false });

        res.json({
            success: true,
            data: { event }
        });

    } catch (error) {
        console.error('Get event error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/events
// @desc    Create new event
// @access  Private (BOD/Admin)
router.post('/', authenticateToken, authorizeRoles('admin', 'bod'), upload.fields([
    { name: 'images', maxCount: 5 },
    { name: 'documents', maxCount: 3 }
]), eventValidation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }

        const eventData = {
            ...req.body,
            organizer: req.user.id,
            metadata: {
                createdBy: req.user.id
            }
        };

        // Handle file uploads
        if (req.files) {
            if (req.files.images) {
                eventData.images = req.files.images.map((file, index) => ({
                    url: `/uploads/events/${file.filename}`,
                    caption: req.body.imageCaptions ? req.body.imageCaptions[index] : '',
                    isPrimary: index === 0
                }));
            }

            if (req.files.documents) {
                eventData.documents = req.files.documents.map(file => ({
                    name: file.originalname,
                    url: `/uploads/events/${file.filename}`,
                    type: file.mimetype,
                    size: file.size
                }));
            }
        }

        // Parse JSON fields
        if (req.body.location && typeof req.body.location === 'string') {
            eventData.location = JSON.parse(req.body.location);
        }
        if (req.body.registrationFee && typeof req.body.registrationFee === 'string') {
            eventData.registrationFee = JSON.parse(req.body.registrationFee);
        }
        if (req.body.requirements && typeof req.body.requirements === 'string') {
            eventData.requirements = JSON.parse(req.body.requirements);
        }
        if (req.body.agenda && typeof req.body.agenda === 'string') {
            eventData.agenda = JSON.parse(req.body.agenda);
        }
        if (req.body.tags && typeof req.body.tags === 'string') {
            eventData.tags = JSON.parse(req.body.tags);
        }

        const event = new Event(eventData);
        await event.save();

        await event.populate('organizer', 'firstName lastName email profileImage');

        res.status(201).json({
            success: true,
            message: 'Event created successfully',
            data: { event }
        });

    } catch (error) {
        console.error('Create event error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   PUT /api/events/:id
// @desc    Update event
// @access  Private (BOD/Admin/Organizer)
router.put('/:id', authenticateToken, upload.fields([
    { name: 'images', maxCount: 5 },
    { name: 'documents', maxCount: 3 }
]), async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        
        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        // Check permissions
        const canEdit = ['admin', 'bod'].includes(req.user.role) || 
                       event.organizer.toString() === req.user.id ||
                       event.coOrganizers.some(co => co.toString() === req.user.id);

        if (!canEdit) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to edit this event'
            });
        }

        // Update event data
        const updateData = { ...req.body };
        updateData.metadata = { ...event.metadata, updatedBy: req.user.id };

        // Handle file uploads
        if (req.files) {
            if (req.files.images) {
                const newImages = req.files.images.map((file, index) => ({
                    url: `/uploads/events/${file.filename}`,
                    caption: req.body.imageCaptions ? req.body.imageCaptions[index] : '',
                    isPrimary: index === 0 && !event.images.some(img => img.isPrimary)
                }));
                updateData.images = [...(event.images || []), ...newImages];
            }

            if (req.files.documents) {
                const newDocuments = req.files.documents.map(file => ({
                    name: file.originalname,
                    url: `/uploads/events/${file.filename}`,
                    type: file.mimetype,
                    size: file.size
                }));
                updateData.documents = [...(event.documents || []), ...newDocuments];
            }
        }

        // Parse JSON fields
        ['location', 'registrationFee', 'requirements', 'agenda', 'tags'].forEach(field => {
            if (req.body[field] && typeof req.body[field] === 'string') {
                try {
                    updateData[field] = JSON.parse(req.body[field]);
                } catch (e) {
                    // Keep original value if parsing fails
                }
            }
        });

        const updatedEvent = await Event.findByIdAndUpdate(
            req.params.id,
            updateData,
            { new: true, runValidators: true }
        ).populate('organizer', 'firstName lastName email profileImage')
         .populate('coOrganizers', 'firstName lastName email profileImage');

        res.json({
            success: true,
            message: 'Event updated successfully',
            data: { event: updatedEvent }
        });

    } catch (error) {
        console.error('Update event error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   DELETE /api/events/:id
// @desc    Delete event
// @access  Private (Admin/BOD)
router.delete('/:id', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        
        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        // Check if event has participants
        if (event.participants.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete event with registered participants. Cancel the event instead.'
            });
        }

        await Event.findByIdAndDelete(req.params.id);

        res.json({
            success: true,
            message: 'Event deleted successfully'
        });

    } catch (error) {
        console.error('Delete event error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   POST /api/events/:id/register
// @desc    Register for event
// @access  Private
router.post('/:id/register', authenticateToken, [
    body('notes').optional().isLength({ max: 500 }).withMessage('Notes cannot exceed 500 characters')
], async (req, res) => {
    try {
        const { notes = '' } = req.body;

        const event = await Event.findById(req.params.id);
        
        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        // Check if event is published
        if (event.status !== 'published') {
            return res.status(400).json({
                success: false,
                message: 'Event is not available for registration'
            });
        }

        // Check if user can register for this event type
        const allowedTypes = ['public'];
        if (req.user.role === 'member') allowedTypes.push('members-only');
        if (req.user.role === 'core') allowedTypes.push('members-only', 'core-only');
        if (['bod', 'admin'].includes(req.user.role)) allowedTypes.push('members-only', 'core-only', 'bod-only');
        
        if (!allowedTypes.includes(event.type)) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to register for this event'
            });
        }

        await event.registerParticipant(req.user.id, notes);

        res.json({
            success: true,
            message: 'Successfully registered for the event',
            data: { event }
        });

    } catch (error) {
        console.error('Event registration error:', error);
        
        if (error.message.includes('already registered') || 
            error.message.includes('full') || 
            error.message.includes('deadline')) {
            return res.status(400).json({
                success: false,
                message: error.message
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to register for event',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   DELETE /api/events/:id/register
// @desc    Cancel event registration
// @access  Private
router.delete('/:id/register', authenticateToken, async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        
        if (!event) {
            return res.status(404).json({
                success: false,
                message: 'Event not found'
            });
        }

        await event.cancelRegistration(req.user.id);

        res.json({
            success: true,
            message: 'Registration cancelled successfully',
            data: { event }
        });

    } catch (error) {
        console.error('Cancel registration error:', error);
        
        if (error.message.includes('not registered')) {
            return res.status(400).json({
                success: false,
                message: error.message
            });
        }

        res.status(500).json({
            success: false,
            message: 'Failed to cancel registration',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// @route   GET /api/events/stats
// @desc    Get event statistics
// @access  Private (Admin/BOD)
router.get('/admin/stats', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const stats = await Event.getStats();

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Get event stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch event statistics',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

module.exports = router;
