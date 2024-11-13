import mongoose from "mongoose";

const courseContentSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        trim: true
    },
    thumbnailUrl: {
        type: String
    },
    videoUrl: {
        type: String
    }
});

const courseSchema = new mongoose.Schema(
    {
        courseName: {
            type: String,
            required: true,
            trim: true
        },
        price: {
            type: Number,
            required: true,
            min: 0
        },
        expiryDate: {
            type: Date,
            required: true
        },
        validityPeriod: {
            duration: {
                type: Number,
                default: 1
            },
            unit: {
                type: String,
                enum: ['days', 'months', 'years'],
                default: 'years'
            }
        },
        status: {
            type: String,
            enum: ['draft', 'published'],
            default: 'draft'
        },
        createdBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        enrolledUsers: [{
            userId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User'
            },
            enrolledAt: {
                type: Date,
                default: Date.now
            },
            validUntil: {
                type: Date,
                required: true
            }
        }],
        isDeleted: {
            type: Boolean,
            default: false
        },
        isActive: {
            type: Boolean,
            default: true
        },
        content: [courseContentSchema]
    },
    { timestamps: true }
);

courseSchema.methods.hasValidAccess = function (userId) {
    const enrollment = this.enrolledUsers.find(
        enrollment => enrollment.userId.toString() === userId.toString()
    );

    if (!enrollment) return false;
    return enrollment.validUntil > new Date();
};


export const Course = mongoose.model("Course", courseSchema);