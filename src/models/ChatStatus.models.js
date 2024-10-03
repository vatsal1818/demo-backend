import mongoose from "mongoose";

const chatStatusSchema = new mongoose.Schema({
    isDeactivated: { type: Boolean, default: false }
});

export const ChatStatus = mongoose.model('ChatStatus', chatStatusSchema);