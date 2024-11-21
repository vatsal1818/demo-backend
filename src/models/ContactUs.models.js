import mongoose from "mongoose";

const ContactUsSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true,
        default: 'Contact Us'
    },
    subtitle: {
        type: String,
        default: 'Get in touch with us'
    },
    address: {
        type: String,
        required: true,
        default: 'Your Address Here'
    },
    email: {
        type: String,
        required: true,
        default: 'contact@example.com'
    },
    phone: {
        type: String,
        required: true,
        default: '+1 234 567 8900'
    },
    socialMedia: {
        facebook: { type: String, default: '' },
        twitter: { type: String, default: '' },
        linkedin: { type: String, default: '' },
        instagram: { type: String, default: '' }
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

export const ContactUs = mongoose.model('ContactUs', ContactUsSchema);