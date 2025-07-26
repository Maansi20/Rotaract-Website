const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const Donation = require('../models/Donation');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

// Validation middleware for donation creation
const validateDonation = [
    body('donor.name')
        .trim()
        .isLength({ min: 2, max: 100 })
        .withMessage('Donor name must be between 2 and 100 characters'),
    body('donor.email')
        .isEmail()
        .normalizeEmail()
        .withMessage('Please provide a valid email address'),
    body('donor.phone')
        .optional()
        .isMobilePhone()
        .withMessage('Please provide a valid phone number'),
    body('amount')
        .isFloat({ min: 0.01 })
        .withMessage('Donation amount must be greater than 0'),
    body('type')
        .isIn(['monetary', 'in-kind', 'service'])
        .withMessage('Invalid donation type'),
    body('category')
        .isIn(['general', 'education', 'health', 'environment', 'community-development', 'emergency-relief', 'other'])
        .withMessage('Invalid donation category'),
    body('paymentMethod')
        .isIn(['credit-card', 'debit-card', 'bank-transfer', 'paypal', 'cash', 'check', 'other'])
        .withMessage('Invalid payment method'),
    body('description')
        .optional()
        .isLength({ max: 500 })
        .withMessage('Description cannot exceed 500 characters')
];

// GET /api/donations - Get all donations (Admin/BOD only)
router.get('/', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;
        
        const filter = {};
        
        // Apply filters
        if (req.query.status) {
            filter.status = req.query.status;
        }
        
        if (req.query.type) {
            filter.type = req.query.type;
        }
        
        if (req.query.category) {
            filter.category = req.query.category;
        }
        
        if (req.query.startDate && req.query.endDate) {
            filter.createdAt = {
                $gte: new Date(req.query.startDate),
                $lte: new Date(req.query.endDate)
            };
        }
        
        const donations = await Donation.find(filter)
            .populate('campaign', 'title')
            .populate('event', 'title')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        
        const total = await Donation.countDocuments(filter);
        
        res.json({
            success: true,
            data: {
                donations,
                pagination: {
                    current: page,
                    pages: Math.ceil(total / limit),
                    total
                }
            }
        });
    } catch (error) {
        console.error('Error fetching donations:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch donations'
        });
    }
});

// GET /api/donations/stats - Get donation statistics (Admin/BOD only)
router.get('/stats', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const startDate = req.query.startDate;
        const endDate = req.query.endDate;
        
        const stats = await Donation.getStats(startDate, endDate);
        
        res.json({
            success: true,
            data: stats
        });
    } catch (error) {
        console.error('Error fetching donation stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch donation statistics'
        });
    }
});

// GET /api/donations/top-donors - Get top donors (Admin/BOD only)
router.get('/top-donors', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const topDonors = await Donation.getTopDonors(limit);
        
        res.json({
            success: true,
            data: topDonors
        });
    } catch (error) {
        console.error('Error fetching top donors:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch top donors'
        });
    }
});

// GET /api/donations/:id - Get single donation
router.get('/:id', authenticateToken, async (req, res) => {
    try {
        const donation = await Donation.findById(req.params.id)
            .populate('campaign', 'title description')
            .populate('event', 'title description startDate')
            .populate('metadata.processedBy', 'name email')
            .populate('metadata.approvedBy', 'name email');
        
        if (!donation) {
            return res.status(404).json({
                success: false,
                message: 'Donation not found'
            });
        }
        
        // Check if user can view this donation
        const canView = req.user.role === 'admin' || 
                       req.user.role === 'bod' || 
                       donation.donor.email === req.user.email;
        
        if (!canView) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        res.json({
            success: true,
            data: donation
        });
    } catch (error) {
        console.error('Error fetching donation:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch donation'
        });
    }
});

// POST /api/donations - Create new donation
router.post('/', validateDonation, async (req, res) => {
    try {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                message: 'Validation failed',
                errors: errors.array()
            });
        }
        
        const donationData = {
            donor: {
                name: req.body.donor.name,
                email: req.body.donor.email,
                phone: req.body.donor.phone,
                address: req.body.donor.address,
                isAnonymous: req.body.donor.isAnonymous || false,
                isRecurring: req.body.donor.isRecurring || false
            },
            amount: req.body.amount,
            currency: req.body.currency || 'USD',
            type: req.body.type,
            category: req.body.category,
            paymentMethod: req.body.paymentMethod,
            description: req.body.description,
            metadata: {
                source: 'website',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent')
            }
        };
        
        // Add campaign or event if specified
        if (req.body.campaign) {
            donationData.campaign = req.body.campaign;
        }
        
        if (req.body.event) {
            donationData.event = req.body.event;
        }
        
        // Handle in-kind donations
        if (req.body.type === 'in-kind' && req.body.inKindDetails) {
            donationData.inKindDetails = req.body.inKindDetails;
        }
        
        // Handle service donations
        if (req.body.type === 'service' && req.body.serviceDetails) {
            donationData.serviceDetails = req.body.serviceDetails;
        }
        
        // Handle recurring donations
        if (req.body.donor.isRecurring && req.body.recurringDetails) {
            donationData.recurringDetails = req.body.recurringDetails;
        }
        
        // Set payment details
        if (req.body.paymentDetails) {
            donationData.paymentDetails = req.body.paymentDetails;
        }
        
        const donation = new Donation(donationData);
        await donation.save();
        
        // In a real application, you would process the payment here
        // For now, we'll mark it as completed for demo purposes
        if (req.body.paymentMethod !== 'cash' && req.body.paymentMethod !== 'check') {
            donation.status = 'completed';
            donation.metadata.processedAt = new Date();
            await donation.save();
        }
        
        res.status(201).json({
            success: true,
            message: 'Donation created successfully',
            data: donation
        });
    } catch (error) {
        console.error('Error creating donation:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to create donation'
        });
    }
});

// PUT /api/donations/:id/status - Update donation status (Admin/BOD only)
router.put('/:id/status', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const { status, notes } = req.body;
        
        if (!['pending', 'completed', 'failed', 'refunded', 'cancelled'].includes(status)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid status'
            });
        }
        
        const donation = await Donation.findById(req.params.id);
        
        if (!donation) {
            return res.status(404).json({
                success: false,
                message: 'Donation not found'
            });
        }
        
        donation.status = status;
        
        if (status === 'completed') {
            donation.metadata.approvedBy = req.user._id;
            donation.metadata.approvedAt = new Date();
        }
        
        if (notes) {
            donation.notes.internal = (donation.notes.internal || '') + `\n${new Date().toISOString()}: ${notes}`;
        }
        
        await donation.save();
        
        res.json({
            success: true,
            message: 'Donation status updated successfully',
            data: donation
        });
    } catch (error) {
        console.error('Error updating donation status:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update donation status'
        });
    }
});

// POST /api/donations/:id/receipt - Generate receipt (Admin/BOD only)
router.post('/:id/receipt', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const donation = await Donation.findById(req.params.id);
        
        if (!donation) {
            return res.status(404).json({
                success: false,
                message: 'Donation not found'
            });
        }
        
        if (donation.status !== 'completed') {
            return res.status(400).json({
                success: false,
                message: 'Can only generate receipt for completed donations'
            });
        }
        
        await donation.generateReceipt();
        
        res.json({
            success: true,
            message: 'Receipt generated successfully',
            data: {
                receiptNumber: donation.receiptNumber,
                receiptUrl: donation.receiptUrl
            }
        });
    } catch (error) {
        console.error('Error generating receipt:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Failed to generate receipt'
        });
    }
});

// POST /api/donations/:id/acknowledgment - Send acknowledgment (Admin/BOD only)
router.post('/:id/acknowledgment', authenticateToken, authorizeRoles('admin', 'bod'), async (req, res) => {
    try {
        const donation = await Donation.findById(req.params.id);
        
        if (!donation) {
            return res.status(404).json({
                success: false,
                message: 'Donation not found'
            });
        }
        
        await donation.sendAcknowledgment();
        
        res.json({
            success: true,
            message: 'Acknowledgment sent successfully'
        });
    } catch (error) {
        console.error('Error sending acknowledgment:', error);
        res.status(500).json({
            success: false,
            message: error.message || 'Failed to send acknowledgment'
        });
    }
});

// GET /api/donations/my-donations - Get current user's donations
router.get('/my/donations', authenticateToken, async (req, res) => {
    try {
        const donations = await Donation.findByDonorEmail(req.user.email)
            .populate('campaign', 'title')
            .populate('event', 'title');
        
        res.json({
            success: true,
            data: donations
        });
    } catch (error) {
        console.error('Error fetching user donations:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch your donations'
        });
    }
});

module.exports = router;
