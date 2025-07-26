const express = require('express');
const User = require('../models/User');
const Event = require('../models/Event');
const Donation = require('../models/Donation');
const Announcement = require('../models/Announcement');
const Contact = require('../models/Contact');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

// @route   GET /dashboard/member
// @desc    Member dashboard
// @access  Private (Member)
router.get('/member', authenticateToken, authorizeRoles('member'), async (req, res) => {
    try {
        // Get user's registered events
        const userEvents = await Event.find({
            'participants.user': req.user.id,
            'participants.status': { $in: ['registered', 'confirmed'] }
        })
        .populate('organizer', 'firstName lastName')
        .sort({ startDate: 1 })
        .limit(5);

        // Get upcoming events user can join
        const upcomingEvents = await Event.find({
            status: 'published',
            startDate: { $gt: new Date() },
            type: { $in: ['public', 'members-only'] },
            'participants.user': { $ne: req.user.id }
        })
        .sort({ startDate: 1 })
        .limit(6);

        // Get recent announcements
        const announcements = await Announcement.findForUser(req.user)
            .limit(5);

        // Get user profile
        const userProfile = await User.findById(req.user.id)
            .select('-password -passwordResetToken -emailVerificationToken -twoFactorSecret');

        res.render('dashboard/member', {
            title: 'Member Dashboard - Rotaract Club',
            user: req.user,
            userProfile,
            userEvents,
            upcomingEvents,
            announcements,
            currentPage: 'dashboard'
        });

    } catch (error) {
        console.error('Member dashboard error:', error);
        res.status(500).render('error', {
            title: 'Error - Rotaract Club',
            message: 'Failed to load dashboard',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// @route   GET /dashboard/core
// @desc    Core team dashboard
// @access  Private (Core)
router.get('/core', authenticateToken, authorizeRoles('core'), async (req, res) => {
    try {
        // Get events assigned to core team member
        const assignedEvents = await Event.find({
            $or: [
                { organizer: req.user.id },
                { coOrganizers: req.user.id }
            ],
            status: { $in: ['published', 'ongoing'] }
        })
        .populate('organizer', 'firstName lastName')
        .sort({ startDate: 1 })
        .limit(10);

        // Get events needing logistics coordination
        const upcomingEvents = await Event.find({
            status: 'published',
            startDate: { $gte: new Date(), $lte: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) } // Next 30 days
        })
        .populate('organizer', 'firstName lastName')
        .sort({ startDate: 1 });

        // Get member list for coordination
        const members = await User.find({
            role: 'member',
            status: 'active'
        })
        .select('firstName lastName email phone')
        .sort({ firstName: 1 })
        .limit(20);

        // Get recent announcements
        const announcements = await Announcement.findForUser(req.user)
            .limit(5);

        // Get statistics
        const stats = {
            totalMembers: await User.countDocuments({ role: 'member', status: 'active' }),
            upcomingEventsCount: upcomingEvents.length,
            assignedEventsCount: assignedEvents.length,
            pendingTasks: assignedEvents.filter(e => e.status === 'published').length
        };

        res.render('dashboard/core', {
            title: 'Core Team Dashboard - Rotaract Club',
            user: req.user,
            assignedEvents,
            upcomingEvents,
            members,
            announcements,
            stats,
            currentPage: 'dashboard'
        });

    } catch (error) {
        console.error('Core dashboard error:', error);
        res.status(500).render('error', {
            title: 'Error - Rotaract Club',
            message: 'Failed to load dashboard',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// @route   GET /dashboard/bod
// @desc    Board of Directors dashboard
// @access  Private (BOD)
router.get('/bod', authenticateToken, authorizeRoles('bod'), async (req, res) => {
    try {
        // Get pending member applications
        const pendingApplications = await User.find({ status: 'pending' })
            .select('firstName lastName email phone interests createdAt')
            .sort({ createdAt: -1 })
            .limit(10);

        // Get events needing approval
        const pendingEvents = await Event.find({ status: 'draft' })
            .populate('organizer', 'firstName lastName email')
            .sort({ createdAt: -1 })
            .limit(10);

        // Get recent donations
        const recentDonations = await Donation.find({ status: 'completed' })
            .sort({ createdAt: -1 })
            .limit(10);

        // Get contact messages needing attention
        const pendingContacts = await Contact.find({
            status: { $in: ['new', 'in-progress'] }
        })
        .populate('assignedTo', 'firstName lastName')
        .sort({ priority: -1, createdAt: -1 })
        .limit(10);

        // Get announcements
        const announcements = await Announcement.findForUser(req.user)
            .limit(5);

        // Get statistics
        const stats = {
            totalMembers: await User.countDocuments({ role: 'member', status: 'active' }),
            pendingApplications: pendingApplications.length,
            pendingEvents: pendingEvents.length,
            totalDonations: await Donation.aggregate([
                { $match: { status: 'completed' } },
                { $group: { _id: null, total: { $sum: '$amount' } } }
            ]).then(result => result[0]?.total || 0),
            pendingContacts: pendingContacts.length,
            activeEvents: await Event.countDocuments({ 
                status: 'published', 
                startDate: { $gt: new Date() } 
            })
        };

        res.render('dashboard/bod', {
            title: 'BOD Dashboard - Rotaract Club',
            user: req.user,
            pendingApplications,
            pendingEvents,
            recentDonations,
            pendingContacts,
            announcements,
            stats,
            currentPage: 'dashboard'
        });

    } catch (error) {
        console.error('BOD dashboard error:', error);
        res.status(500).render('error', {
            title: 'Error - Rotaract Club',
            message: 'Failed to load dashboard',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// @route   GET /dashboard/admin
// @desc    Admin dashboard
// @access  Private (Admin)
router.get('/admin', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        // Get comprehensive statistics
        const [userStats, eventStats, donationStats, contactStats] = await Promise.all([
            User.getStats(),
            Event.getStats(),
            Donation.getStats(),
            Contact.getStats()
        ]);

        // Get recent activity
        const recentUsers = await User.find({ status: 'active' })
            .sort({ createdAt: -1 })
            .limit(5)
            .select('firstName lastName email role createdAt');

        const recentEvents = await Event.find({ status: 'published' })
            .populate('organizer', 'firstName lastName')
            .sort({ createdAt: -1 })
            .limit(5);

        const recentDonations = await Donation.find({ status: 'completed' })
            .sort({ createdAt: -1 })
            .limit(5);

        // Get system health metrics
        const systemHealth = {
            totalUsers: await User.countDocuments(),
            activeUsers: await User.countDocuments({ status: 'active' }),
            totalEvents: await Event.countDocuments(),
            publishedEvents: await Event.countDocuments({ status: 'published' }),
            totalDonations: await Donation.countDocuments({ status: 'completed' }),
            pendingContacts: await Contact.countDocuments({ status: { $in: ['new', 'in-progress'] } }),
            overdueContacts: (await Contact.findOverdue()).length
        };

        // Get monthly growth data for charts
        const monthlyGrowth = await User.aggregate([
            {
                $match: {
                    createdAt: { $gte: new Date(new Date().getFullYear(), 0, 1) }
                }
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
            {
                $sort: { '_id.year': 1, '_id.month': 1 }
            }
        ]);

        res.render('dashboard/admin', {
            title: 'Admin Dashboard - Rotaract Club',
            user: req.user,
            userStats,
            eventStats,
            donationStats,
            contactStats,
            recentUsers,
            recentEvents,
            recentDonations,
            systemHealth,
            monthlyGrowth,
            currentPage: 'dashboard'
        });

    } catch (error) {
        console.error('Admin dashboard error:', error);
        res.status(500).render('error', {
            title: 'Error - Rotaract Club',
            message: 'Failed to load dashboard',
            error: process.env.NODE_ENV === 'development' ? error : {}
        });
    }
});

// API endpoints for dashboard data

// @route   GET /dashboard/api/member/stats
// @desc    Get member dashboard statistics
// @access  Private (Member)
router.get('/api/member/stats', authenticateToken, authorizeRoles('member'), async (req, res) => {
    try {
        const stats = {
            registeredEvents: await Event.countDocuments({
                'participants.user': req.user.id,
                'participants.status': { $in: ['registered', 'confirmed'] }
            }),
            attendedEvents: await Event.countDocuments({
                'participants.user': req.user.id,
                'participants.status': 'attended'
            }),
            upcomingEvents: await Event.countDocuments({
                'participants.user': req.user.id,
                'participants.status': { $in: ['registered', 'confirmed'] },
                startDate: { $gt: new Date() }
            }),
            unreadAnnouncements: await Announcement.countDocuments({
                status: 'published',
                $or: [
                    { visibility: 'public' },
                    { visibility: 'members' },
                    { 'targetAudience.specificUsers': req.user.id }
                ],
                'interactions.views.user': { $ne: req.user.id }
            })
        };

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Member stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics'
        });
    }
});

// @route   GET /dashboard/api/core/stats
// @desc    Get core team dashboard statistics
// @access  Private (Core)
router.get('/api/core/stats', authenticateToken, authorizeRoles('core'), async (req, res) => {
    try {
        const stats = {
            assignedEvents: await Event.countDocuments({
                $or: [
                    { organizer: req.user.id },
                    { coOrganizers: req.user.id }
                ],
                status: { $in: ['published', 'ongoing'] }
            }),
            upcomingEvents: await Event.countDocuments({
                status: 'published',
                startDate: { $gte: new Date(), $lte: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) }
            }),
            totalMembers: await User.countDocuments({ role: 'member', status: 'active' }),
            pendingTasks: await Event.countDocuments({
                $or: [
                    { organizer: req.user.id },
                    { coOrganizers: req.user.id }
                ],
                status: 'published',
                startDate: { $gt: new Date() }
            })
        };

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Core stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics'
        });
    }
});

// @route   GET /dashboard/api/bod/stats
// @desc    Get BOD dashboard statistics
// @access  Private (BOD)
router.get('/api/bod/stats', authenticateToken, authorizeRoles('bod'), async (req, res) => {
    try {
        const stats = {
            totalMembers: await User.countDocuments({ role: 'member', status: 'active' }),
            pendingApplications: await User.countDocuments({ status: 'pending' }),
            pendingEvents: await Event.countDocuments({ status: 'draft' }),
            totalDonations: await Donation.aggregate([
                { $match: { status: 'completed' } },
                { $group: { _id: null, total: { $sum: '$amount' } } }
            ]).then(result => result[0]?.total || 0),
            pendingContacts: await Contact.countDocuments({ status: { $in: ['new', 'in-progress'] } }),
            activeEvents: await Event.countDocuments({ 
                status: 'published', 
                startDate: { $gt: new Date() } 
            })
        };

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('BOD stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics'
        });
    }
});

// @route   GET /dashboard/api/admin/stats
// @desc    Get admin dashboard statistics
// @access  Private (Admin)
router.get('/api/admin/stats', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const [userStats, eventStats, donationStats, contactStats] = await Promise.all([
            User.getStats(),
            Event.getStats(),
            Donation.getStats(),
            Contact.getStats()
        ]);

        const systemHealth = {
            totalUsers: await User.countDocuments(),
            activeUsers: await User.countDocuments({ status: 'active' }),
            totalEvents: await Event.countDocuments(),
            publishedEvents: await Event.countDocuments({ status: 'published' }),
            totalDonations: await Donation.countDocuments({ status: 'completed' }),
            pendingContacts: await Contact.countDocuments({ status: { $in: ['new', 'in-progress'] } }),
            overdueContacts: (await Contact.findOverdue()).length
        };

        res.json({
            success: true,
            data: {
                userStats,
                eventStats,
                donationStats,
                contactStats,
                systemHealth
            }
        });

    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch statistics'
        });
    }
});

module.exports = router;
