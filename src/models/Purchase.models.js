import mongoose from "mongoose";

const purchaseSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'User ID is required']
    },
    course: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course',
        required: [true, 'Course ID is required']
    },
    // amount: {
    //     type: Number,
    //     required: [true, 'Purchase amount is required'],
    //     min: [0, 'Amount cannot be negative']
    // },
    status: {
        type: String,
        enum: ['pending', 'completed', 'failed', 'refunded'],
        default: 'pending'
    },
    purchaseDate: {
        type: Date,
        default: Date.now
    },
    completedAt: {
        type: Date
    },
    // paymentMethod: {
    //     type: String,
    //     required: [true, 'Payment method is required']
    // },
    // transactionId: {
    //     type: String,
    //     unique: true,
    //     sparse: true  // Allows null/undefined values to exist
    // },
    progress: {
        type: Number,
        default: 0,
        min: 0,
        max: 100
    },
    lastAccessedAt: {
        type: Date,
        default: Date.now
    },
    completedContent: [{
        contentId: {
            type: mongoose.Schema.Types.ObjectId,
            required: true
        },
        completedAt: {
            type: Date,
            default: Date.now
        }
    }]
}, {
    timestamps: true
});

// Indexes for better query performance
purchaseSchema.index({ user: 1, course: 1 }, { unique: true });
purchaseSchema.index({ status: 1 });
purchaseSchema.index({ purchaseDate: -1 });

// Virtual field for calculating completion percentage
purchaseSchema.virtual('completionPercentage').get(function () {
    if (!this.course || !this.course.content) return 0;
    const totalContent = this.course.content.length;
    if (totalContent === 0) return 0;
    return (this.completedContent.length / totalContent) * 100;
});

// Instance method to mark content as completed
purchaseSchema.methods.markContentComplete = async function (contentId) {
    if (!this.completedContent.find(item => item.contentId.equals(contentId))) {
        this.completedContent.push({ contentId });
        this.progress = this.completionPercentage;
        this.lastAccessedAt = new Date();
        await this.save();
    }
};

// Static method to get user's purchase status for a course
purchaseSchema.statics.getUserPurchaseStatus = async function (userId, courseId) {
    return await this.findOne({ user: userId, course: courseId })
        .select('status progress lastAccessedAt')
        .lean();
};

// Pre-save middleware to update progress
purchaseSchema.pre('save', function (next) {
    if (this.isModified('completedContent')) {
        this.progress = this.completionPercentage;
    }
    next();
});

export const Purchase = mongoose.model('Purchase', purchaseSchema);
