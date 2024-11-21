import mongoose from "mongoose";

const BannerSchema = new mongoose.Schema(
    {
        bannerUrl: {
            type: String,
            default: ''
        },
        link: {
            type: String,
            default: '#'
        },
    },
    { timestamps: true }
)

export const Banner = mongoose.model("Banner", BannerSchema);