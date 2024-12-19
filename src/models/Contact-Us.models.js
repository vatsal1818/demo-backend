import mongoose from "mongoose";

const contact_UsSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    titleSpan: {
        type: String,
        required: true
    },
    paragraph: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        validate: {
            validator: function (v) {
                return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
            },
            message: props => `${props.value} is not a valid email address!`
        }
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

export const Contact_Us = mongoose.model('Contact_Us', contact_UsSchema);