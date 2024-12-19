import mongoose from "mongoose";

const AdminContentSchema = new mongoose.Schema({
    upperTitle:
    {
        type: String,
        required: true,
        default: 'Ready to Learn ?'
    },
    title: {
        type: String,
        required: true,
        default: 'Welcome to Our Website'
    },
    paragraph: {
        type: String,
        required: true,
        default: 'Add Your Paragraph here'
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
    },
});

export const AdminContent = mongoose.model('AdminContent', AdminContentSchema);