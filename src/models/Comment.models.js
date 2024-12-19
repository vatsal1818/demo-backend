import mongoose from "mongoose";

const CommentSchema = new mongoose.Schema({
    course: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course',
        required: true
    },
    courseContent: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Course.content',
        required: true
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    content: {
        type: String,
        required: true
    },
    adminReply: {
        content: {
            type: String,
            default: null
        },
        repliedAt: {
            type: Date,
            default: null
        },
        repliedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            default: null
        }
    }
}, {
    timestamps: true
});

export const Comment = mongoose.model('Comment', CommentSchema);