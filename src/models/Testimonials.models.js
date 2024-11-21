import mongoose from "mongoose";

const TestimonialSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Name is required'],
        trim: true
    },
    comment: {
        type: String,
        required: [true, 'Comment is required'],
        trim: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

export const Testimonial = mongoose.model('Testimonial', TestimonialSchema);
