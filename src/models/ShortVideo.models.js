import mongoose from "mongoose";

const videoSchema = new mongoose.Schema({
    embedCode:
    {
        type: String,
        required: true
    },
    createdAt:
    {
        type: Date,
        default: Date.now
    },
});

export const Video = mongoose.model('Video', videoSchema);