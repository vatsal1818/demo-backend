import mongoose from "mongoose";

const stockTradeSchema = new mongoose.Schema(
    {
        strikeName: {
            type: String,
            required: true,
        },
        quantity: {
            type: Number,
            required: true,
        },
        buyPrice: {
            type: Number,
            required: true,
        },
        sellPrice: {
            type: Number,
            required: true,
        },
        charges: {
            type: Number,
            default: 0,
        },
        brokerage: {
            type: Number,
            default: 0,
        },
        profit: {
            type: Number,
            default: null,
        },
        loss: {
            type: Number,
            default: null,
        },
        userId:
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        dailyChargesUpdated:
        {
            type: Boolean,
            default: false

        },
    },
    { timestamps: true }
);

export const StockTrade = mongoose.model('StockTrade', stockTradeSchema);
