import mongoose from "mongoose";

const purchaseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    courseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Course', required: true },
    progress: { type: Number, default: 0 }, // Track course progress
    purchasedAt: { type: Date, default: Date.now }
});

export const Purchase = mongoose.model('Purchase', purchaseSchema);
