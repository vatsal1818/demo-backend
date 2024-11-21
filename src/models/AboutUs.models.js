import mongoose from "mongoose";

const whyChooseUsSchema = new mongoose.Schema({
    title: String,
    reasons: [{
        title: String,
        description: String
    }],
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

const AboutUsSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        default: 'This is About Page'
    },
    paragraph: {
        type: String,
        required: true,
        default: 'Add something About You'
    },
    button: {
        type: String,
        required: true,
        default: 'view'
    },
    imageUrl: {
        type: String,
        default: ''
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

export const AboutUs = mongoose.model('AboutUs', AboutUsSchema);
export const WhyChooseUs = mongoose.model('WhyChooseUs', whyChooseUsSchema);