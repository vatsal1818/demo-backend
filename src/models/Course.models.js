import mongoose from "mongoose";

const fileSchema = new mongoose.Schema({
    filename: String,
    contentType: String,
    data: Buffer,
    uploadDate: {
        type: Date,
        default: Date.now
    },
    size: Number
});

export const File = mongoose.model('File', fileSchema);

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
    },
    attachments: [{
        fileName: {
            type: String,
            required: true
        },
        fileUrl: {
            type: String,
            required: true
        },
        fileType: {
            type: String,
            required: true
        },
        uploadedAt: {
            type: Date,
            default: Date.now
        }
    }]
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
        offerPrice: {
            type: Number,
            min: 0
        },
        courseDescription: {
            type: String,
            trim: true
        },
        courseThumbnailUrl: {
            type: String,
            default: ''
        },
        courseVideoUrl: {
            type: String,
            default: ""
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