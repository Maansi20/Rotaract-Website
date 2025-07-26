const mongoose = require('mongoose');

const announcementSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Announcement title is required'],
        trim: true,
        maxlength: [100, 'Title cannot exceed 100 characters']
    },
    content: {
        type: String,
        required: [true, 'Announcement content is required'],
        maxlength: [5000, 'Content cannot exceed 5000 characters']
    },
    summary: {
        type: String,
        maxlength: [200, 'Summary cannot exceed 200 characters']
    },
    type: {
        type: String,
        enum: ['general', 'urgent', 'event', 'meeting', 'deadline', 'celebration', 'policy', 'other'],
        default: 'general'
    },
    priority: {
        type: String,
        enum: ['low', 'normal', 'high', 'urgent'],
        default: 'normal'
    },
    status: {
        type: String,
        enum: ['draft', 'scheduled', 'published', 'archived'],
        default: 'draft'
    },
    visibility: {
        type: String,
        enum: ['public', 'members', 'bod', 'core', 'admin'],
        default: 'members'
    },
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'Author is required']
    },
    publishDate: {
        type: Date,
        default: Date.now
    },
    expiryDate: {
        type: Date,
        default: null
    },
    scheduledFor: {
        type: Date,
        default: null
    },
    images: [{
        url: String,
        caption: String,
        alt: String
    }],
    attachments: [{
        name: String,
        url: String,
        type: String,
        size: Number
    }],
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    targetAudience: {
        roles: [{
            type: String,
            enum: ['member', 'bod', 'core', 'admin']
        }],
        specificUsers: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }],
        excludeUsers: [{
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        }]
    },
    notifications: {
        email: {
            enabled: {
                type: Boolean,
                default: true
            },
            sent: {
                type: Boolean,
                default: false
            },
            sentAt: Date,
            recipients: [{
                user: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'User'
                },
                email: String,
                status: {
                    type: String,
                    enum: ['pending', 'sent', 'delivered', 'failed', 'bounced'],
                    default: 'pending'
                },
                sentAt: Date,
                deliveredAt: Date
            }]
        },
        push: {
            enabled: {
                type: Boolean,
                default: false
            },
            sent: {
                type: Boolean,
                default: false
            },
            sentAt: Date
        },
        sms: {
            enabled: {
                type: Boolean,
                default: false
            },
            sent: {
                type: Boolean,
                default: false
            },
            sentAt: Date
        }
    },
    interactions: {
        views: [{
            user: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            viewedAt: {
                type: Date,
                default: Date.now
            },
            ipAddress: String,
            userAgent: String
        }],
        likes: [{
            user: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            likedAt: {
                type: Date,
                default: Date.now
            }
        }],
        comments: [{
            user: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                required: true
            },
            content: {
                type: String,
                required: true,
                maxlength: [1000, 'Comment cannot exceed 1000 characters']
            },
            createdAt: {
                type: Date,
                default: Date.now
            },
            isEdited: {
                type: Boolean,
                default: false
            },
            editedAt: Date,
            replies: [{
                user: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'User',
                    required: true
                },
                content: {
                    type: String,
                    required: true,
                    maxlength: [500, 'Reply cannot exceed 500 characters']
                },
                createdAt: {
                    type: Date,
                    default: Date.now
                }
            }]
        }]
    },
    analytics: {
        totalViews: {
            type: Number,
            default: 0
        },
        uniqueViews: {
            type: Number,
            default: 0
        },
        totalLikes: {
            type: Number,
            default: 0
        },
        totalComments: {
            type: Number,
            default: 0
        },
        engagementRate: {
            type: Number,
            default: 0
        }
    },
    isSticky: {
        type: Boolean,
        default: false
    },
    allowComments: {
        type: Boolean,
        default: true
    },
    allowLikes: {
        type: Boolean,
        default: true
    },
    moderationRequired: {
        type: Boolean,
        default: false
    },
    metadata: {
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        updatedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        approvedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        approvedAt: Date,
        publishedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        publishedAt: Date
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual for is expired
announcementSchema.virtual('isExpired').get(function() {
    return this.expiryDate && this.expiryDate < new Date();
});

// Virtual for is scheduled
announcementSchema.virtual('isScheduled').get(function() {
    return this.status === 'scheduled' && this.scheduledFor && this.scheduledFor > new Date();
});

// Virtual for should be published
announcementSchema.virtual('shouldBePublished').get(function() {
    return this.status === 'scheduled' && this.scheduledFor && this.scheduledFor <= new Date();
});

// Virtual for reading time (words per minute = 200)
announcementSchema.virtual('readingTime').get(function() {
    const wordCount = this.content.split(/\s+/).length;
    const minutes = Math.ceil(wordCount / 200);
    return minutes;
});

// Virtual for engagement rate calculation
announcementSchema.virtual('calculatedEngagementRate').get(function() {
    if (this.analytics.uniqueViews === 0) return 0;
    const engagements = this.analytics.totalLikes + this.analytics.totalComments;
    return ((engagements / this.analytics.uniqueViews) * 100).toFixed(2);
});

// Indexes for performance
announcementSchema.index({ status: 1, publishDate: -1 });
announcementSchema.index({ visibility: 1, status: 1 });
announcementSchema.index({ author: 1, createdAt: -1 });
announcementSchema.index({ type: 1, priority: 1 });
announcementSchema.index({ tags: 1 });
announcementSchema.index({ scheduledFor: 1, status: 1 });
announcementSchema.index({ expiryDate: 1 });
announcementSchema.index({ title: 'text', content: 'text', summary: 'text' });

// Pre-save middleware
announcementSchema.pre('save', function(next) {
    // Auto-publish scheduled announcements
    if (this.shouldBePublished) {
        this.status = 'published';
        this.metadata.publishedAt = new Date();
        this.metadata.publishedBy = this.metadata.updatedBy || this.author;
    }
    
    // Update analytics
    if (this.interactions) {
        this.analytics.totalViews = this.interactions.views.length;
        this.analytics.uniqueViews = new Set(
            this.interactions.views.map(v => v.user?.toString()).filter(Boolean)
        ).size;
        this.analytics.totalLikes = this.interactions.likes.length;
        this.analytics.totalComments = this.interactions.comments.length;
        this.analytics.engagementRate = this.calculatedEngagementRate;
    }
    
    // Generate summary if not provided
    if (!this.summary && this.content) {
        this.summary = this.content.substring(0, 197) + '...';
    }
    
    next();
});

// Instance method to add view
announcementSchema.methods.addView = function(userId, ipAddress, userAgent) {
    // Check if user already viewed (to avoid duplicate views)
    const existingView = this.interactions.views.find(v => 
        v.user && v.user.toString() === userId?.toString()
    );
    
    if (!existingView) {
        this.interactions.views.push({
            user: userId,
            ipAddress,
            userAgent,
            viewedAt: new Date()
        });
    }
    
    return this.save();
};

// Instance method to toggle like
announcementSchema.methods.toggleLike = function(userId) {
    const likeIndex = this.interactions.likes.findIndex(l => 
        l.user.toString() === userId.toString()
    );
    
    if (likeIndex > -1) {
        // Unlike
        this.interactions.likes.splice(likeIndex, 1);
        return this.save().then(() => ({ liked: false }));
    } else {
        // Like
        this.interactions.likes.push({
            user: userId,
            likedAt: new Date()
        });
        return this.save().then(() => ({ liked: true }));
    }
};

// Instance method to add comment
announcementSchema.methods.addComment = function(userId, content) {
    if (!this.allowComments) {
        throw new Error('Comments are not allowed on this announcement');
    }
    
    this.interactions.comments.push({
        user: userId,
        content: content.trim(),
        createdAt: new Date()
    });
    
    return this.save();
};

// Instance method to add reply to comment
announcementSchema.methods.addReply = function(commentId, userId, content) {
    const comment = this.interactions.comments.id(commentId);
    if (!comment) {
        throw new Error('Comment not found');
    }
    
    comment.replies.push({
        user: userId,
        content: content.trim(),
        createdAt: new Date()
    });
    
    return this.save();
};

// Instance method to send notifications
announcementSchema.methods.sendNotifications = async function() {
    if (this.status !== 'published') {
        throw new Error('Can only send notifications for published announcements');
    }
    
    // In a real application, you would integrate with email/SMS/push notification services
    // For now, we'll just mark notifications as sent
    if (this.notifications.email.enabled) {
        this.notifications.email.sent = true;
        this.notifications.email.sentAt = new Date();
    }
    
    if (this.notifications.push.enabled) {
        this.notifications.push.sent = true;
        this.notifications.push.sentAt = new Date();
    }
    
    if (this.notifications.sms.enabled) {
        this.notifications.sms.sent = true;
        this.notifications.sms.sentAt = new Date();
    }
    
    return this.save();
};

// Static method to find published announcements
announcementSchema.statics.findPublished = function(visibility = null) {
    const query = {
        status: 'published',
        $or: [
            { expiryDate: null },
            { expiryDate: { $gt: new Date() } }
        ]
    };
    
    if (visibility) {
        query.visibility = visibility;
    }
    
    return this.find(query)
        .sort({ isSticky: -1, publishDate: -1 })
        .populate('author', 'firstName lastName email profileImage');
};

// Static method to find announcements for user
announcementSchema.statics.findForUser = function(user) {
    const query = {
        status: 'published',
        $or: [
            { expiryDate: null },
            { expiryDate: { $gt: new Date() } }
        ],
        $and: [
            {
                $or: [
                    { visibility: 'public' },
                    { visibility: user.role },
                    { 'targetAudience.specificUsers': user._id },
                    { 'targetAudience.roles': user.role }
                ]
            },
            {
                'targetAudience.excludeUsers': { $ne: user._id }
            }
        ]
    };
    
    return this.find(query)
        .sort({ isSticky: -1, publishDate: -1 })
        .populate('author', 'firstName lastName email profileImage');
};

// Static method to find scheduled announcements
announcementSchema.statics.findScheduled = function() {
    return this.find({
        status: 'scheduled',
        scheduledFor: { $lte: new Date() }
    });
};

// Static method to get announcement statistics
announcementSchema.statics.getStats = async function() {
    const stats = await this.aggregate([
        {
            $group: {
                _id: '$status',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const typeStats = await this.aggregate([
        {
            $match: { status: 'published' }
        },
        {
            $group: {
                _id: '$type',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const engagementStats = await this.aggregate([
        {
            $match: { status: 'published' }
        },
        {
            $group: {
                _id: null,
                totalViews: { $sum: '$analytics.totalViews' },
                totalLikes: { $sum: '$analytics.totalLikes' },
                totalComments: { $sum: '$analytics.totalComments' },
                averageEngagement: { $avg: '$analytics.engagementRate' }
            }
        }
    ]);
    
    return {
        statusStats: stats,
        typeStats,
        engagement: engagementStats[0] || {
            totalViews: 0,
            totalLikes: 0,
            totalComments: 0,
            averageEngagement: 0
        }
    };
};

module.exports = mongoose.model('Announcement', announcementSchema);
