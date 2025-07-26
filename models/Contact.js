const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true,
        maxlength: [100, 'Name cannot exceed 100 characters']
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
        type: String,
        trim: true,
        match: [/^[\+]?[1-9][\d]{0,15}$/, 'Please enter a valid phone number']
    },
    subject: {
        type: String,
        required: [true, 'Subject is required'],
        trim: true,
        maxlength: [200, 'Subject cannot exceed 200 characters']
    },
    message: {
        type: String,
        required: [true, 'Message is required'],
        trim: true,
        maxlength: [2000, 'Message cannot exceed 2000 characters']
    },
    category: {
        type: String,
        enum: ['general', 'membership', 'events', 'volunteering', 'donations', 'partnerships', 'media', 'complaints', 'suggestions', 'other'],
        default: 'general'
    },
    priority: {
        type: String,
        enum: ['low', 'normal', 'high', 'urgent'],
        default: 'normal'
    },
    status: {
        type: String,
        enum: ['new', 'in-progress', 'resolved', 'closed', 'spam'],
        default: 'new'
    },
    source: {
        type: String,
        enum: ['website', 'email', 'phone', 'social-media', 'event', 'referral', 'other'],
        default: 'website'
    },
    assignedTo: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    attachments: [{
        name: String,
        url: String,
        type: String,
        size: Number
    }],
    responses: [{
        respondedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        message: {
            type: String,
            required: true,
            maxlength: [2000, 'Response cannot exceed 2000 characters']
        },
        method: {
            type: String,
            enum: ['email', 'phone', 'in-person', 'other'],
            default: 'email'
        },
        isPublic: {
            type: Boolean,
            default: false
        },
        respondedAt: {
            type: Date,
            default: Date.now
        },
        attachments: [{
            name: String,
            url: String,
            type: String,
            size: Number
        }]
    }],
    followUps: [{
        scheduledFor: {
            type: Date,
            required: true
        },
        message: String,
        method: {
            type: String,
            enum: ['email', 'phone', 'in-person', 'other'],
            default: 'email'
        },
        assignedTo: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        completed: {
            type: Boolean,
            default: false
        },
        completedAt: Date,
        completedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        notes: String
    }],
    satisfaction: {
        rating: {
            type: Number,
            min: 1,
            max: 5
        },
        feedback: String,
        submittedAt: Date
    },
    metadata: {
        ipAddress: String,
        userAgent: String,
        referrer: String,
        utm: {
            source: String,
            medium: String,
            campaign: String,
            term: String,
            content: String
        },
        browserInfo: {
            name: String,
            version: String,
            os: String
        },
        location: {
            country: String,
            region: String,
            city: String,
            timezone: String
        }
    },
    internalNotes: [{
        addedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        note: {
            type: String,
            required: true,
            maxlength: [1000, 'Note cannot exceed 1000 characters']
        },
        addedAt: {
            type: Date,
            default: Date.now
        },
        isImportant: {
            type: Boolean,
            default: false
        }
    }],
    relatedContacts: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Contact'
    }],
    duplicateOf: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Contact',
        default: null
    },
    autoResponded: {
        type: Boolean,
        default: false
    },
    autoRespondedAt: Date,
    firstResponseTime: Date, // Time when first response was sent
    resolutionTime: Date,    // Time when marked as resolved
    reopenedCount: {
        type: Number,
        default: 0
    },
    lastReopenedAt: Date
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual for response time (in hours)
contactSchema.virtual('responseTime').get(function() {
    if (this.firstResponseTime && this.createdAt) {
        return Math.round((this.firstResponseTime - this.createdAt) / (1000 * 60 * 60));
    }
    return null;
});

// Virtual for resolution time (in hours)
contactSchema.virtual('resolutionTimeHours').get(function() {
    if (this.resolutionTime && this.createdAt) {
        return Math.round((this.resolutionTime - this.createdAt) / (1000 * 60 * 60));
    }
    return null;
});

// Virtual for is overdue (more than 24 hours without response)
contactSchema.virtual('isOverdue').get(function() {
    if (this.status === 'resolved' || this.status === 'closed') {
        return false;
    }
    
    const now = new Date();
    const hoursSinceCreated = (now - this.createdAt) / (1000 * 60 * 60);
    
    // If no response yet and more than 24 hours old
    if (!this.firstResponseTime && hoursSinceCreated > 24) {
        return true;
    }
    
    // If last response was more than 48 hours ago
    if (this.responses.length > 0) {
        const lastResponse = this.responses[this.responses.length - 1];
        const hoursSinceLastResponse = (now - lastResponse.respondedAt) / (1000 * 60 * 60);
        return hoursSinceLastResponse > 48;
    }
    
    return false;
});

// Virtual for has pending follow-ups
contactSchema.virtual('hasPendingFollowUps').get(function() {
    return this.followUps.some(f => !f.completed && f.scheduledFor <= new Date());
});

// Indexes for performance
contactSchema.index({ email: 1 });
contactSchema.index({ status: 1, createdAt: -1 });
contactSchema.index({ category: 1, status: 1 });
contactSchema.index({ assignedTo: 1, status: 1 });
contactSchema.index({ priority: 1, status: 1 });
contactSchema.index({ tags: 1 });
contactSchema.index({ 'followUps.scheduledFor': 1, 'followUps.completed': 1 });
contactSchema.index({ subject: 'text', message: 'text' });

// Pre-save middleware
contactSchema.pre('save', function(next) {
    // Set first response time when first response is added
    if (this.isModified('responses') && this.responses.length > 0 && !this.firstResponseTime) {
        this.firstResponseTime = this.responses[0].respondedAt;
    }
    
    // Set resolution time when status changes to resolved
    if (this.isModified('status') && this.status === 'resolved' && !this.resolutionTime) {
        this.resolutionTime = new Date();
    }
    
    // Track reopening
    if (this.isModified('status') && this.status === 'new' && this.resolutionTime) {
        this.reopenedCount += 1;
        this.lastReopenedAt = new Date();
        this.resolutionTime = null; // Clear resolution time
    }
    
    // Auto-categorize based on keywords in subject/message
    if (this.isNew && this.category === 'general') {
        const text = (this.subject + ' ' + this.message).toLowerCase();
        
        if (text.includes('member') || text.includes('join') || text.includes('registration')) {
            this.category = 'membership';
        } else if (text.includes('event') || text.includes('meeting') || text.includes('workshop')) {
            this.category = 'events';
        } else if (text.includes('volunteer') || text.includes('help') || text.includes('participate')) {
            this.category = 'volunteering';
        } else if (text.includes('donate') || text.includes('donation') || text.includes('fund')) {
            this.category = 'donations';
        } else if (text.includes('partner') || text.includes('collaboration') || text.includes('sponsor')) {
            this.category = 'partnerships';
        } else if (text.includes('complaint') || text.includes('problem') || text.includes('issue')) {
            this.category = 'complaints';
        } else if (text.includes('suggest') || text.includes('idea') || text.includes('improve')) {
            this.category = 'suggestions';
        }
    }
    
    next();
});

// Instance method to add response
contactSchema.methods.addResponse = function(userId, message, method = 'email', isPublic = false, attachments = []) {
    this.responses.push({
        respondedBy: userId,
        message: message.trim(),
        method,
        isPublic,
        attachments,
        respondedAt: new Date()
    });
    
    // Update status if it's new
    if (this.status === 'new') {
        this.status = 'in-progress';
    }
    
    return this.save();
};

// Instance method to add internal note
contactSchema.methods.addInternalNote = function(userId, note, isImportant = false) {
    this.internalNotes.push({
        addedBy: userId,
        note: note.trim(),
        isImportant,
        addedAt: new Date()
    });
    
    return this.save();
};

// Instance method to schedule follow-up
contactSchema.methods.scheduleFollowUp = function(scheduledFor, message, method = 'email', assignedTo = null) {
    this.followUps.push({
        scheduledFor,
        message,
        method,
        assignedTo: assignedTo || this.assignedTo
    });
    
    return this.save();
};

// Instance method to complete follow-up
contactSchema.methods.completeFollowUp = function(followUpId, userId, notes = '') {
    const followUp = this.followUps.id(followUpId);
    if (!followUp) {
        throw new Error('Follow-up not found');
    }
    
    followUp.completed = true;
    followUp.completedAt = new Date();
    followUp.completedBy = userId;
    followUp.notes = notes;
    
    return this.save();
};

// Instance method to assign to user
contactSchema.methods.assignTo = function(userId) {
    this.assignedTo = userId;
    if (this.status === 'new') {
        this.status = 'in-progress';
    }
    
    return this.save();
};

// Instance method to mark as spam
contactSchema.methods.markAsSpam = function() {
    this.status = 'spam';
    return this.save();
};

// Instance method to send auto-response
contactSchema.methods.sendAutoResponse = async function() {
    if (this.autoResponded) {
        return;
    }
    
    // In a real application, you would integrate with an email service
    // For now, we'll just mark it as auto-responded
    this.autoResponded = true;
    this.autoRespondedAt = new Date();
    
    return this.save();
};

// Static method to find by email
contactSchema.statics.findByEmail = function(email) {
    return this.find({ email: email.toLowerCase() })
        .sort({ createdAt: -1 });
};

// Static method to find overdue contacts
contactSchema.statics.findOverdue = function() {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    return this.find({
        status: { $in: ['new', 'in-progress'] },
        $or: [
            {
                // No response and created more than 24 hours ago
                responses: { $size: 0 },
                createdAt: { $lt: twentyFourHoursAgo }
            },
            {
                // Last response more than 48 hours ago
                'responses.0': { $exists: true },
                'responses.respondedAt': { $lt: new Date(Date.now() - 48 * 60 * 60 * 1000) }
            }
        ]
    });
};

// Static method to find pending follow-ups
contactSchema.statics.findPendingFollowUps = function() {
    return this.find({
        'followUps.completed': false,
        'followUps.scheduledFor': { $lte: new Date() }
    });
};

// Static method to get contact statistics
contactSchema.statics.getStats = async function(startDate, endDate) {
    const matchStage = {};
    
    if (startDate && endDate) {
        matchStage.createdAt = {
            $gte: new Date(startDate),
            $lte: new Date(endDate)
        };
    }
    
    const stats = await this.aggregate([
        { $match: matchStage },
        {
            $group: {
                _id: '$status',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const categoryStats = await this.aggregate([
        { $match: matchStage },
        {
            $group: {
                _id: '$category',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const responseTimeStats = await this.aggregate([
        {
            $match: {
                ...matchStage,
                firstResponseTime: { $exists: true }
            }
        },
        {
            $project: {
                responseTimeHours: {
                    $divide: [
                        { $subtract: ['$firstResponseTime', '$createdAt'] },
                        1000 * 60 * 60
                    ]
                }
            }
        },
        {
            $group: {
                _id: null,
                averageResponseTime: { $avg: '$responseTimeHours' },
                minResponseTime: { $min: '$responseTimeHours' },
                maxResponseTime: { $max: '$responseTimeHours' }
            }
        }
    ]);
    
    return {
        statusStats: stats,
        categoryStats,
        responseTime: responseTimeStats[0] || {
            averageResponseTime: 0,
            minResponseTime: 0,
            maxResponseTime: 0
        }
    };
};

// Static method to find duplicates
contactSchema.statics.findDuplicates = async function() {
    return this.aggregate([
        {
            $group: {
                _id: { email: '$email', subject: '$subject' },
                contacts: { $push: '$$ROOT' },
                count: { $sum: 1 }
            }
        },
        {
            $match: { count: { $gt: 1 } }
        }
    ]);
};

module.exports = mongoose.model('Contact', contactSchema);
