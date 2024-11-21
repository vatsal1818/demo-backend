import mongoose from "mongoose";

const CommentSchema = new mongoose.Schema({
    course: {  // Changed from courseId to course
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course',
        required: true
    },
    user: {    // Changed from userId to user
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    content: {
        type: String,
        required: true,
        trim: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

export const Comment = mongoose.model('Comment', CommentSchema);