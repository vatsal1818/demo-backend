import mongoose from "mongoose";

const messageSchema = new mongoose.Schema({
    sender: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    receiver: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
    },
    text: {
        type: String,
        required: function () {
            return !this.fileUrl; // Require `text` only if `fileUrl` is not present
        }
    },
    fileUrl: {
        type: String,
        required: function () {
            return !this.text; // Require `fileUrl` only if `text` is not present
        }
    },
    messageType: {
        type: String,
        enum: ['broadcast', 'private'],
        required: true
    }
},
    { timestamps: true }
);

export const Message = mongoose.model("Message", messageSchema);

export async function saveMessage(sender, receiver, text, messageType, fileUrl) {
    try {
        // Ensure receiver is null for broadcast messages
        const message = new Message({
            sender,
            receiver: messageType === 'broadcast' ? null : receiver,
            text,
            fileUrl,
            messageType
        });
        return await message.save();
    } catch (error) {
        console.error("Error saving message:", error);
        throw error; // Rethrow the error so it can be caught in the API route
    }
}

