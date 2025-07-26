const mongoose = require('mongoose');

const eventSchema = new mongoose.Schema({
    title: {
        type: String,
        required: [true, 'Event title is required'],
        trim: true,
        maxlength: [100, 'Title cannot exceed 100 characters']
    },
    description: {
        type: String,
        required: [true, 'Event description is required'],
        maxlength: [2000, 'Description cannot exceed 2000 characters']
    },
    shortDescription: {
        type: String,
        maxlength: [200, 'Short description cannot exceed 200 characters']
    },
    category: {
        type: String,
        required: [true, 'Event category is required'],
        enum: ['community-service', 'fundraising', 'social', 'professional-development', 'environmental', 'health', 'education', 'other'],
        default: 'community-service'
    },
    type: {
        type: String,
        enum: ['public', 'members-only', 'bod-only', 'core-only'],
        default: 'public'
    },
    status: {
        type: String,
        enum: ['draft', 'published', 'ongoing', 'completed', 'cancelled'],
        default: 'draft'
    },
    startDate: {
        type: Date,
        required: [true, 'Start date is required']
    },
    endDate: {
        type: Date,
        required: [true, 'End date is required']
    },
    registrationDeadline: {
        type: Date,
        required: false
    },
    location: {
        name: {
            type: String,
            required: [true, 'Location name is required']
        },
        address: {
            street: String,
            city: String,
            state: String,
            zipCode: String,
            country: String
        },
        coordinates: {
            latitude: Number,
            longitude: Number
        },
        isVirtual: {
            type: Boolean,
            default: false
        },
        virtualLink: String
    },
    organizer: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'Event organizer is required']
    },
    coOrganizers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    maxParticipants: {
        type: Number,
        min: [1, 'Maximum participants must be at least 1'],
        default: null // null means unlimited
    },
    currentParticipants: {
        type: Number,
        default: 0,
        min: 0
    },
    registrationRequired: {
        type: Boolean,
        default: true
    },
    registrationFee: {
        amount: {
            type: Number,
            min: 0,
            default: 0
        },
        currency: {
            type: String,
            default: 'USD'
        }
    },
    images: [{
        url: String,
        caption: String,
        isPrimary: {
            type: Boolean,
            default: false
        }
    }],
    documents: [{
        name: String,
        url: String,
        type: String, // pdf, doc, etc.
        size: Number
    }],
    requirements: [{
        type: String,
        trim: true
    }],
    agenda: [{
        time: String,
        activity: String,
        duration: Number, // in minutes
        speaker: String
    }],
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    participants: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        registrationDate: {
            type: Date,
            default: Date.now
        },
        status: {
            type: String,
            enum: ['registered', 'confirmed', 'attended', 'cancelled', 'no-show'],
            default: 'registered'
        },
        paymentStatus: {
            type: String,
            enum: ['pending', 'paid', 'refunded', 'waived'],
            default: 'pending'
        },
        notes: String
    }],
    feedback: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        rating: {
            type: Number,
            min: 1,
            max: 5,
            required: true
        },
        comment: String,
        submittedAt: {
            type: Date,
            default: Date.now
        }
    }],
    budget: {
        totalBudget: {
            type: Number,
            min: 0,
            default: 0
        },
        expenses: [{
            category: String,
            description: String,
            amount: Number,
            receipt: String, // URL to receipt image/document
            approvedBy: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            approvedAt: Date
        }],
        revenue: [{
            source: String,
            description: String,
            amount: Number,
            receivedAt: Date
        }]
    },
    socialMedia: {
        facebook: String,
        twitter: String,
        instagram: String,
        linkedin: String,
        hashtags: [String]
    },
    notifications: {
        reminderSent: {
            type: Boolean,
            default: false
        },
        followUpSent: {
            type: Boolean,
            default: false
        },
        lastNotificationSent: Date
    },
    analytics: {
        views: {
            type: Number,
            default: 0
        },
        registrations: {
            type: Number,
            default: 0
        },
        cancellations: {
            type: Number,
            default: 0
        },
        attendance: {
            type: Number,
            default: 0
        }
    },
    isRecurring: {
        type: Boolean,
        default: false
    },
    recurringPattern: {
        frequency: {
            type: String,
            enum: ['daily', 'weekly', 'monthly', 'yearly'],
            default: 'weekly'
        },
        interval: {
            type: Number,
            min: 1,
            default: 1
        },
        endDate: Date,
        occurrences: Number
    },
    parentEvent: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event',
        default: null
    },
    childEvents: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event'
    }],
    metadata: {
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        updatedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        approvedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        approvedAt: Date
    }
}, {
    timestamps: true,
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual for event duration
eventSchema.virtual('duration').get(function() {
    if (this.startDate && this.endDate) {
        return Math.ceil((this.endDate - this.startDate) / (1000 * 60 * 60)); // hours
    }
    return 0;
});

// Virtual for available spots
eventSchema.virtual('availableSpots').get(function() {
    if (this.maxParticipants) {
        return Math.max(0, this.maxParticipants - this.currentParticipants);
    }
    return null; // unlimited
});

// Virtual for is full
eventSchema.virtual('isFull').get(function() {
    if (this.maxParticipants) {
        return this.currentParticipants >= this.maxParticipants;
    }
    return false;
});

// Virtual for is past event
eventSchema.virtual('isPast').get(function() {
    return this.endDate < new Date();
});

// Virtual for is upcoming
eventSchema.virtual('isUpcoming').get(function() {
    return this.startDate > new Date();
});

// Virtual for is ongoing
eventSchema.virtual('isOngoing').get(function() {
    const now = new Date();
    return this.startDate <= now && this.endDate >= now;
});

// Virtual for average rating
eventSchema.virtual('averageRating').get(function() {
    if (this.feedback && this.feedback.length > 0) {
        const sum = this.feedback.reduce((acc, fb) => acc + fb.rating, 0);
        return (sum / this.feedback.length).toFixed(1);
    }
    return 0;
});

// Virtual for primary image
eventSchema.virtual('primaryImage').get(function() {
    if (this.images && this.images.length > 0) {
        const primary = this.images.find(img => img.isPrimary);
        return primary ? primary.url : this.images[0].url;
    }
    return null;
});

// Indexes for performance
eventSchema.index({ startDate: 1, status: 1 });
eventSchema.index({ category: 1, status: 1 });
eventSchema.index({ organizer: 1 });
eventSchema.index({ 'location.coordinates': '2dsphere' });
eventSchema.index({ tags: 1 });
eventSchema.index({ title: 'text', description: 'text' });

// Pre-save middleware
eventSchema.pre('save', function(next) {
    // Ensure end date is after start date
    if (this.endDate <= this.startDate) {
        next(new Error('End date must be after start date'));
        return;
    }
    
    // Set registration deadline if not provided
    if (!this.registrationDeadline) {
        this.registrationDeadline = new Date(this.startDate.getTime() - 24 * 60 * 60 * 1000); // 1 day before
    }
    
    // Update current participants count
    if (this.participants) {
        this.currentParticipants = this.participants.filter(p => 
            ['registered', 'confirmed', 'attended'].includes(p.status)
        ).length;
    }
    
    next();
});

// Instance method to register participant
eventSchema.methods.registerParticipant = function(userId, notes = '') {
    // Check if already registered
    const existingParticipant = this.participants.find(p => 
        p.user.toString() === userId.toString()
    );
    
    if (existingParticipant) {
        throw new Error('User is already registered for this event');
    }
    
    // Check if event is full
    if (this.isFull) {
        throw new Error('Event is full');
    }
    
    // Check if registration is still open
    if (this.registrationDeadline && new Date() > this.registrationDeadline) {
        throw new Error('Registration deadline has passed');
    }
    
    this.participants.push({
        user: userId,
        notes: notes,
        paymentStatus: this.registrationFee.amount > 0 ? 'pending' : 'waived'
    });
    
    this.analytics.registrations += 1;
    
    return this.save();
};

// Instance method to cancel registration
eventSchema.methods.cancelRegistration = function(userId) {
    const participantIndex = this.participants.findIndex(p => 
        p.user.toString() === userId.toString()
    );
    
    if (participantIndex === -1) {
        throw new Error('User is not registered for this event');
    }
    
    this.participants[participantIndex].status = 'cancelled';
    this.analytics.cancellations += 1;
    
    return this.save();
};

// Instance method to mark attendance
eventSchema.methods.markAttendance = function(userId, attended = true) {
    const participant = this.participants.find(p => 
        p.user.toString() === userId.toString()
    );
    
    if (!participant) {
        throw new Error('User is not registered for this event');
    }
    
    participant.status = attended ? 'attended' : 'no-show';
    
    if (attended) {
        this.analytics.attendance += 1;
    }
    
    return this.save();
};

// Static method to find upcoming events
eventSchema.statics.findUpcoming = function(limit = 10) {
    return this.find({
        startDate: { $gt: new Date() },
        status: 'published'
    })
    .sort({ startDate: 1 })
    .limit(limit)
    .populate('organizer', 'firstName lastName email');
};

// Static method to find events by category
eventSchema.statics.findByCategory = function(category) {
    return this.find({
        category: category,
        status: 'published'
    })
    .sort({ startDate: 1 })
    .populate('organizer', 'firstName lastName email');
};

// Static method to find events near location
eventSchema.statics.findNearLocation = function(longitude, latitude, maxDistance = 10000) {
    return this.find({
        'location.coordinates': {
            $near: {
                $geometry: {
                    type: 'Point',
                    coordinates: [longitude, latitude]
                },
                $maxDistance: maxDistance
            }
        },
        status: 'published'
    });
};

// Static method for event statistics
eventSchema.statics.getStats = async function() {
    const stats = await this.aggregate([
        {
            $group: {
                _id: '$status',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const categoryStats = await this.aggregate([
        {
            $match: { status: 'published' }
        },
        {
            $group: {
                _id: '$category',
                count: { $sum: 1 }
            }
        }
    ]);
    
    const monthlyStats = await this.aggregate([
        {
            $match: {
                startDate: { $gte: new Date(new Date().getFullYear(), 0, 1) }
            }
        },
        {
            $group: {
                _id: {
                    year: { $year: '$startDate' },
                    month: { $month: '$startDate' }
                },
                count: { $sum: 1 },
                totalParticipants: { $sum: '$currentParticipants' }
            }
        },
        {
            $sort: { '_id.year': 1, '_id.month': 1 }
        }
    ]);
    
    return { statusStats: stats, categoryStats, monthlyStats };
};

module.exports = mongoose.model('Event', eventSchema);
