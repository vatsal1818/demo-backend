import mongoose from "mongoose";

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
    experience: {
        type: String,
        required: true,
    },
    experienceSpan: {
        type: String,
        required: true,
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

const AboutUs2Schema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        default: 'This is'
    },
    titleSpan: {
        type: String,
        required: true,
        default: 'About Page'
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


export const AboutUs2 = mongoose.model('AboutUs2', AboutUs2Schema);
export const AboutUs = mongoose.model('AboutUs', AboutUsSchema);