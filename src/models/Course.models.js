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
        content: [courseContentSchema]
    },
    { timestamps: true }
);

export const Course = mongoose.model("Course", courseSchema);