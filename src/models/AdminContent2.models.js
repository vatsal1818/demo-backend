import mongoose from "mongoose";

const AdminPage2Schema = new mongoose.Schema({
    imageUrl: {
        type: String,
        default: ''
    },
    title: {
        type: String,
        required: true,
        default: 'Welcome to Page 2'
    },
    paragraph: {
        type: String,
        required: true,
        default: 'This is the content for Page 2'
    },
    sections: [
        {
            iconImage: {
                type: String,
                default: ''
            },
            sectionTitle: {
                type: String,
                required: true,
                default: 'Section Title'
            },
            sectionParagraph: {
                type: String,
                required: true,
                default: 'Section Paragraph'
            }
        }
    ],
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

export const AdminPage2 = mongoose.model('AdminPage2', AdminPage2Schema);