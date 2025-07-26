const mongoose = require('mongoose');

const donationSchema = new mongoose.Schema({
    donor: {
        name: {
            type: String,
            required: [true, 'Donor name is required'],
            trim: true
        },
        email: {
            type: String,
            required: [true, 'Donor email is required'],
            lowercase: true,
            trim: true,
            match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
        },
        phone: {
            type: String,
            trim: true
        },
        address: {
            street: String,
            city: String,
            state: String,
            zipCode: String,
            country: String
        },
        isAnonymous: {
            type: Boolean,
            default: false
        },
        isRecurring: {
            type: Boolean,
            default: false
        }
    },
    amount: {
        type: Number,
        required: [true, 'Donation amount is required'],
        min: [0.01, 'Donation amount must be greater than 0']
    },
    currency: {
        type: String,
        default: 'USD',
        uppercase: true
    },
    type: {
        type: String,
        enum: ['monetary', 'in-kind', 'service'],
        default: 'monetary'
    },
    category: {
        type: String,
        enum: ['general', 'education', 'health', 'environment', 'community-development', 'emergency-relief', 'other'],
        default: 'general'
    },
    campaign: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Campaign',
        default: null
    },
    event: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Event',
        default: null
    },
    paymentMethod: {
        type: String,
        enum: ['credit-card', 'debit-card', 'bank-transfer', 'paypal', 'cash', 'check', 'other'],
        required: [true, 'Payment method is required']
    },
    paymentDetails: {
        transactionId: String,
        paymentGateway: String,
        gatewayTransactionId: String,
        last4Digits: String, // For card payments
        bankName: String, // For bank transfers
        checkNumber: String // For check payments
    },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'refunded', 'cancelled'],
        default: 'pending'
    },
    description: {
        type: String,
        maxlength: [500, 'Description cannot exceed 500 characters']
    },
    inKindDetails: {
        items: [{
            name: String,
            quantity: Number,
            estimatedValue: Number,
            condition: {
                type: String,
                enum: ['new', 'like-new', 'good', 'fair', 'poor']
            }
        }],
        totalEstimatedValue: Number
    },
    serviceDetails: {
        serviceType: String,
        hoursContributed: Number,
        skillsProvided: [String],
        estimatedValue: Number
    },
    recurringDetails: {
        frequency: {
            type: String,
            enum: ['weekly', 'monthly', 'quarterly', 'yearly']
        },
        nextDonationDate: Date,
        endDate: Date,
        totalOccurrences: Number,
        currentOccurrence: {
            type: Number,
            default: 1
        }
    },
    taxDeductible: {
        type: Boolean,
        default: true
    },
    receiptGenerated: {
        type: Boolean,
        default: false
    },
    receiptNumber: {
        type: String,
        unique: true,
        sparse: true
    },
    receiptUrl: String,
    acknowledgmentSent: {
        type: Boolean,
        default: false
    },
    acknowledgmentSentAt: Date,
    notes: {
        internal: String, // Internal notes for staff
        public: String   // Public thank you message
    },
    tags: [{
        type: String,
        trim: true,
        lowercase: true
    }],
    metadata: {
        source: {
            type: String,
            enum: ['website', 'event', 'email-campaign', 'social-media', 'phone', 'mail', 'other'],
            default: 'website'
        },
        referrer: String,
        ipAddress: String,
        userAgent: String,
        utm: {
            source: String,
            medium: String,
            campaign: String,
            term: String,
            content: String
        },
        processedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        processedAt: Date,
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

// Virtual for display amount
donationSchema.virtual('displayAmount').get(function() {
    return `${this.currency} ${this.amount.toFixed(2)}`;
});

// Virtual for donor display name
donationSchema.virtual('donorDisplayName').get(function() {
    return this.donor.isAnonymous ? 'Anonymous Donor' : this.donor.name;
});

// Virtual for is recurring
donationSchema.virtual('isRecurring').get(function() {
    return this.donor.isRecurring && this.recurringDetails && this.recurringDetails.frequency;
});

// Indexes for performance
donationSchema.index({ 'donor.email': 1 });
donationSchema.index({ status: 1, createdAt: -1 });
donationSchema.index({ campaign: 1, status: 1 });
donationSchema.index({ event: 1, status: 1 });
donationSchema.index({ type: 1, category: 1 });
donationSchema.index({ receiptNumber: 1 });
donationSchema.index({ 'recurringDetails.nextDonationDate': 1 });

// Pre-save middleware
donationSchema.pre('save', function(next) {
    // Generate receipt number if completed and not already generated
    if (this.status === 'completed' && !this.receiptNumber) {
        const year = new Date().getFullYear();
        const month = String(new Date().getMonth() + 1).padStart(2, '0');
        const random = Math.random().toString(36).substr(2, 6).toUpperCase();
        this.receiptNumber = `RC-${year}${month}-${random}`;
    }
    
    // Set processed date when status changes to completed
    if (this.isModified('status') && this.status === 'completed' && !this.metadata.processedAt) {
        this.metadata.processedAt = new Date();
    }
    
    // Calculate total estimated value for in-kind donations
    if (this.type === 'in-kind' && this.inKindDetails && this.inKindDetails.items) {
        this.inKindDetails.totalEstimatedValue = this.inKindDetails.items.reduce((total, item) => {
            return total + (item.estimatedValue || 0);
        }, 0);
    }
    
    next();
});

// Instance method to generate receipt
donationSchema.methods.generateReceipt = async function() {
    if (this.receiptGenerated) {
        throw new Error('Receipt already generated for this donation');
    }
    
    // In a real application, you would integrate with a PDF generation service
    // For now, we'll just mark it as generated
    this.receiptGenerated = true;
    this.receiptUrl = `/receipts/${this.receiptNumber}.pdf`;
    
    return this.save();
};

// Instance method to send acknowledgment
donationSchema.methods.sendAcknowledgment = async function() {
    if (this.acknowledgmentSent) {
        throw new Error('Acknowledgment already sent for this donation');
    }
    
    // In a real application, you would integrate with an email service
    // For now, we'll just mark it as sent
    this.acknowledgmentSent = true;
    this.acknowledgmentSentAt = new Date();
    
    return this.save();
};

// Instance method to process refund
donationSchema.methods.processRefund = async function(reason) {
    if (this.status !== 'completed') {
        throw new Error('Can only refund completed donations');
    }
    
    this.status = 'refunded';
    this.notes.internal = (this.notes.internal || '') + `\nRefund processed: ${reason}`;
    
    return this.save();
};

// Static method to find donations by donor email
donationSchema.statics.findByDonorEmail = function(email) {
    return this.find({ 'donor.email': email.toLowerCase() })
        .sort({ createdAt: -1 });
};

// Static method to find donations by campaign
donationSchema.statics.findByCampaign = function(campaignId) {
    return this.find({ campaign: campaignId, status: 'completed' })
        .sort({ createdAt: -1 });
};

// Static method to get donation statistics
donationSchema.statics.getStats = async function(startDate, endDate) {
    const matchStage = {
        status: 'completed'
    };
    
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
                _id: null,
                totalAmount: { $sum: '$amount' },
                totalDonations: { $sum: 1 },
                averageDonation: { $avg: '$amount' },
                uniqueDonors: { $addToSet: '$donor.email' }
            }
        },
        {
            $project: {
                totalAmount: 1,
                totalDonations: 1,
                averageDonation: { $round: ['$averageDonation', 2] },
                uniqueDonorsCount: { $size: '$uniqueDonors' }
            }
        }
    ]);
    
    const categoryStats = await this.aggregate([
        { $match: matchStage },
        {
            $group: {
                _id: '$category',
                totalAmount: { $sum: '$amount' },
                count: { $sum: 1 }
            }
        },
        { $sort: { totalAmount: -1 } }
    ]);
    
    const monthlyStats = await this.aggregate([
        { $match: matchStage },
        {
            $group: {
                _id: {
                    year: { $year: '$createdAt' },
                    month: { $month: '$createdAt' }
                },
                totalAmount: { $sum: '$amount' },
                count: { $sum: 1 }
            }
        },
        { $sort: { '_id.year': 1, '_id.month': 1 } }
    ]);
    
    return {
        overall: stats[0] || { totalAmount: 0, totalDonations: 0, averageDonation: 0, uniqueDonorsCount: 0 },
        byCategory: categoryStats,
        byMonth: monthlyStats
    };
};

// Static method to find recurring donations due
donationSchema.statics.findRecurringDue = function() {
    return this.find({
        'donor.isRecurring': true,
        'recurringDetails.nextDonationDate': { $lte: new Date() },
        status: 'completed'
    });
};

// Static method to get top donors
donationSchema.statics.getTopDonors = async function(limit = 10) {
    return this.aggregate([
        { $match: { status: 'completed' } },
        {
            $group: {
                _id: '$donor.email',
                donorName: { $first: '$donor.name' },
                totalAmount: { $sum: '$amount' },
                donationCount: { $sum: 1 },
                lastDonation: { $max: '$createdAt' },
                isAnonymous: { $first: '$donor.isAnonymous' }
            }
        },
        { $sort: { totalAmount: -1 } },
        { $limit: limit }
    ]);
};

module.exports = mongoose.model('Donation', donationSchema);
