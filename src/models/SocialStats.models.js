import mongoose from "mongoose";

const SocialStatsSchema = new mongoose.Schema({
    youtube: {
        title: {
            type: String,
            default: 'YouTube Subscribers',
            required: true
        },
        count: {
            type: Number,
            default: 0,
            required: true
        }
    },
    instagram: {
        title: {
            type: String,
            default: 'Instagram Followers',
            required: true
        },
        count: {
            type: Number,
            default: 0,
            required: true
        }
    },
    telegram: {
        title: {
            type: String,
            default: 'Telegram Subscribers',
            required: true
        },
        count: {
            type: Number,
            default: 0,
            required: true
        }
    },
    playstore: {
        title: {
            type: String,
            default: 'Play Store Downloads',
            required: true
        },
        count: {
            type: Number,
            default: 0,
            required: true
        }
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

export const SocialStats = mongoose.model('SocialStats', SocialStatsSchema);