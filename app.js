import express from "express";
import cors from "cors";
import { User } from "./src/models/User.models.js";
import { Message } from "./src/models/Message.models.js";
import { ApiError } from "./src/utils/ApiErrors.js";
import { ApiResponse } from "./src/utils/ApiResponse.js";
import { asyncHandler } from "./src/utils/AsynceHandler.js";
import { VerifyJWT } from "./src/middlewares/Auth.middleware.js";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import { Server } from 'socket.io';
import { saveMessage } from "./src/models/Message.models.js"
import { ChatStatus } from "./src/models/ChatStatus.models.js";
import mongoose from "mongoose";
import upload from "./src/middlewares/Multer.middleware.js";
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from "path";
import { StockTrade } from "./src/models/StockTrade.models.js";
import { Course } from "./src/models/Course.models.js";
import { uploadOnCloudinary } from "./src/Cloudinary/Cloudinary.js";
import cloudinary from "cloudinary"
import { Purchase } from "./src/models/Purchase.models.js";
import { calculateExpiryDate } from "./src/utils/Helper.js";


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();

const uploadPath = path.join(__dirname, 'uploads');

const allowedOrigins = ['http://localhost:3000', 'http://localhost:5173', 'http://192.168.31.22'];

const corsOptions = {
    origin: function (origin, callback) {
        if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use('/uploads', express.static(uploadPath));

const io = new Server({
    cors: {
        origin: "*",
        methods: ["GET", "POST",],
        credentials: true,
    }
});

let adminSocket = null;
let chatDeactivationStatus = false; // Initialize a flag to track chat deactivation status
const userSockets = new Map(); // To store user sockets with their IDs


io.on("connection", (socket) => {
    console.log("User connected", socket.id);

    socket.on("register-admin", () => {
        adminSocket = socket;
        console.log("Admin registered:", socket.id);
    });

    socket.on("register-user", async (userId) => {
        console.log("Registering user:", userId);
        userSockets.set(socket.id, { userId, socket });
        console.log("User registered:", userId, socket.id);

        // Fetch and send the user's chat status
        try {
            const user = await User.findById(userId);
            if (user) {
                socket.emit("chat-status-changed", { isChatActive: user.isChatActive });
            }
        } catch (error) {
            console.error("Error fetching user chat status:", error);
        }
    });

    socket.on("admin-message", async (data) => {
        console.log("Admin broadcast:", data);
        socket.broadcast.emit("admin-broadcast", data);

        // Save broadcast message to the database
        try {
            const admin = await User.findOne({ role: 'admin' });
            if (admin) {
                // Note: No receiver for broadcast message
                await saveMessage(admin._id, null, data.message, 'broadcast');
            }
        } catch (error) {
            console.error("Error saving broadcast message:", error);
        }
    });

    socket.on("admin-private-message", async ({ userId, message, fileUrl }) => {
        console.log("Admin private message:", userId, message, fileUrl);

        // Find the socket.id for the given userId
        let userSocketId = null;
        for (const [socketId, data] of userSockets.entries()) {
            if (data.userId === userId) {
                userSocketId = socketId;
                break;
            }
        }

        if (userSocketId) {
            const userSocketData = userSockets.get(userSocketId);
            if (userSocketData && userSocketData.socket) {
                console.log("Emitting to user:", userId, "Socket ID:", userSocketId);
                userSocketData.socket.emit("admin-private-message", { message, fileUrl });

                // Save private message to the database
                try {
                    const user = await User.findOne({ _id: userId });
                    const admin = await User.findOne({ role: 'admin' });
                    if (user && admin) {
                        await saveMessage(admin._id, user._id, message, 'private', fileUrl);
                    }
                } catch (error) {
                    console.error("Error saving private message:", error);
                }
            } else {
                console.log("User socket data not found:", userId, userSocketId);
            }
        } else {
            console.log("User not found:", userId);
        }
    });

    socket.on("user-to-admin", async (data) => {
        console.log("Received user message data:", data);

        let user;
        try {
            user = await User.findOne({ _id: data.sender });
        } catch (error) {
            console.error("Error finding user:", error);
        }

        if (!user) {
            console.log("User not found in database");
            return;
        }

        // Check if the user's chat is active
        if (!user.isChatActive) {
            console.log("User's chat is deactivated. Message not processed.");
            // Optionally, you can send a message back to the user informing them that their chat is deactivated
            const userSocket = userSockets.get(data.sender);
            if (userSocket) {
                userSocket.emit("chat-deactivated");
            }
            return;
        }

        if (adminSocket) {
            console.log("Forwarding message to admin socket:", adminSocket.id);
            adminSocket.emit("user-to-admin", {
                ...data,
                username: user.username
            });
        } else {
            console.log("Admin socket not connected");
        }
    });

    socket.on("admin-force-logout", ({ userId }) => {
        // Find the socket connection for this user
        const userSocket = userSockets.get(userId);

        if (userSocket && typeof userSocket.emit === 'function') {
            // Emit a force-logout event to the user
            userSocket.emit("force-logout");
        } else {
            console.error(`Socket for user ${userId} not found or invalid.`);
        }

        // Invalidate the user's session in your backend (optional)
    });


    socket.on('admin-toggle-user-chat', (data) => {
        const { userId, isChatActive } = data;
        io.to(userId).emit('chat-status-update', { isChatActive });
        console.log(`User ${userId} chat status updated to ${isChatActive}`);
    });

    socket.on("call-offer", async ({ to, offer, type }) => {
        console.log(`Received call offer from ${socket.id} to ${to}`);

        let recipientSocket;
        const admin = await User.findOne({ role: 'admin' });

        if (to === admin._id.toString()) {
            // Call offer is for admin
            recipientSocket = adminSocket;
            console.log("Admin socket:", adminSocket ? adminSocket.id : "Admin not connected");
        } else {
            // Call offer is for a user
            const userSocketEntry = Array.from(userSockets.entries()).find(([_, data]) => data.userId === to);
            recipientSocket = userSocketEntry ? userSocketEntry[1].socket : null;
            console.log(`User socket: ${recipientSocket ? recipientSocket.id : 'User not connected'}`);
        }

        if (recipientSocket) {
            recipientSocket.emit("call-offer", { from: socket.id, offer, type });
            console.log(`Sent call offer to ${to} (socket id: ${recipientSocket.id})`);
        } else {
            console.log(`Recipient ${to} not found or not connected`);
        }

        socket.callEnded = false;
    });

    socket.on("call-answer", async ({ to, answer }) => {
        console.log(`Received call-answer from ${socket.id} for ${to}`);

        let recipientSocket;

        try {
            // Find the admin
            const admin = await User.findOne({ role: 'admin' });

            // Check if the recipient is the admin or a user
            if (to === adminSocket.id) {
                recipientSocket = adminSocket;
                console.log("Recipient is admin. Admin socket:", adminSocket ? adminSocket.id : "Admin not connected");
            } else {
                const userSocketEntry = Array.from(userSockets.entries()).find(([id, _]) => id === to);
                recipientSocket = userSocketEntry ? userSocketEntry[1].socket : null;
                console.log(`Recipient is user. User socket: ${recipientSocket ? recipientSocket.id : 'User not connected'}`);
            }

            console.log('Current userSockets:', Array.from(userSockets.keys()));

            // Send the answer if recipientSocket is found
            if (recipientSocket) {
                console.log(`Sending call-answer to ${to} (socket id: ${recipientSocket.id})`);
                recipientSocket.emit("call-answer", { from: socket.id, answer });
            } else {
                console.log(`Recipient ${to} not found or not connected`);
            }
        } catch (error) {
            console.error("Error in call-answer:", error);
        }
    });

    socket.on("ice-candidate", async ({ to, candidate }) => {
        let recipientSocket;
        const admin = await User.findOne({ role: 'admin' });

        if (to === admin._id.toString()) {
            recipientSocket = adminSocket;
        } else {
            const userSocketEntry = Array.from(userSockets.entries()).find(([id, _]) => id === to);
            recipientSocket = userSocketEntry ? userSocketEntry[1].socket : null;
        }

        if (recipientSocket) {
            recipientSocket.emit("ice-candidate", { from: socket.id, candidate });
        } else {
            console.log(`Recipient ${to} not found or not connected`);
        }
    });

    socket.on("end-call", async ({ to }) => {
        console.log("Ending call", new Date().toISOString()); // Log the time of ending the call
        let recipientSocket;

        // Cache admin's information or retrieve once
        const admin = await User.findOne({ role: 'admin' });

        if (to === admin._id.toString()) {
            recipientSocket = adminSocket;
        } else {
            for (const [socketId, userData] of userSockets) {
                if (userData.userId === to) {
                    recipientSocket = userData.socket;
                    break;
                }
            }
        }

        // Ensure the recipient exists and the call hasn't already ended
        if (recipientSocket && !socket.callEnded) {
            socket.callEnded = true; // Set the flag to true when ending the call
            recipientSocket.emit("end-call", { from: socket.id });
            console.log("Call ended successfully", new Date().toISOString());

            // Optionally, clear the flag after a brief timeout to avoid delays or issues
            setTimeout(() => {
                socket.callEnded = false; // Reset the flag after 1 second
            }, 1000);
        } else if (!recipientSocket) {
            console.log(`Recipient ${to} not found or not connected`);
        } else {
            console.log("Call already ended");
        }
    });


    socket.on("call-rejected", async ({ to }) => {
        console.log(`Call rejected by ${socket.id}`);
        let recipientSocket;
        const admin = await User.findOne({ role: 'admin' });

        if (to === admin._id.toString()) {
            // Call rejection is for admin
            recipientSocket = adminSocket;


        } else {
            // Call rejection is for a user
            recipientSocket = socket;
        }

        if (recipientSocket) {
            recipientSocket.emit("call-rejected", { from: socket.id });
            console.log(`Sent call rejection to ${to}`);

            // Also end the call for the rejecting user
            socket.emit("end-call", { from: to });
        } else {
            console.log(`Recipient ${to} not found or not connected`);
        }
    });

    socket.on("broadcast-call-offer", async ({ offer, type }) => {
        console.log(`Received broadcast call offer from admin ${socket.id}`);

        const admin = await User.findOne({ role: 'admin' });
        if (socket.id !== adminSocket.id) {
            console.log("Unauthorized: Only admin can initiate broadcast calls");
            return;
        }

        // Get all connected user sockets
        const connectedUsers = Array.from(userSockets.values());

        // Send the call offer to all connected users
        connectedUsers.forEach(userData => {
            userData.socket.emit("broadcast-call-offer", { from: admin._id.toString(), offer, type, isBroadcast: true });
            console.log(`Sent broadcast call offer to user ${userData.userId}`);
        });

        socket.broadcastCallActive = true;
    });

    // Handle broadcast call answers
    socket.on("broadcast-call-answer", async ({ answer }) => {
        console.log(`Received broadcast call answer from user ${socket.id}`);

        const admin = await User.findOne({ role: 'admin' });

        if (adminSocket) {
            adminSocket.emit("broadcast-call-answer", { from: socket.id, answer });
            console.log(`Sent broadcast call answer to admin`);
        } else {
            console.log("Admin not connected");
        }
    });

    // Handle broadcast ICE candidates
    socket.on("broadcast-ice-candidate", async ({ candidate }) => {
        console.log(`Received broadcast ICE candidate from ${socket.id}`);

        const admin = await User.findOne({ role: 'admin' });

        if (socket.id === adminSocket.id) {
            // Admin is sending ICE candidate to all users
            userSockets.forEach((userData, socketId) => {
                userData.socket.emit("ice-candidate", { from: admin._id.toString(), candidate, isBroadcast: true });
            });
        } else {
            // User is sending ICE candidate to admin
            if (adminSocket) {
                adminSocket.emit("broadcast-ice-candidate", { from: socket.id, candidate });
            } else {
                console.log("Admin not connected");
            }
        }
    });

    // End broadcast call
    socket.on("end-broadcast-call", async () => {
        console.log(`Ending broadcast call from ${socket.id}`);

        const admin = await User.findOne({ role: 'admin' });

        if (socket.id !== adminSocket.id) {
            console.log("Unauthorized: Only admin can end broadcast calls");
            return;
        }

        userSockets.forEach((userData, socketId) => {
            userData.socket.emit("end-call", { from: admin._id.toString(), isBroadcast: true });
        });

        socket.broadcastCallActive = false;
        console.log("Broadcast call ended successfully");
    });

    // Handle user leaving broadcast call
    socket.on("leave-broadcast-call", async () => {
        console.log(`User ${socket.id} leaving broadcast call`);

        if (adminSocket) {
            adminSocket.emit("user-left-broadcast-call", { userId: socket.id });
        }
    });

    socket.on('request-user-socket-ids', async (userIds) => {
        console.log('Received request for user socket IDs:', userIds);

        const socketIds = {};

        // Iterate through the userSockets Map to find socket IDs for the requested user IDs
        userSockets.forEach((userData, socketId) => {
            if (userIds.includes(userData.userId)) {
                socketIds[userData.userId] = socketId;
            }
        });

        console.log('Sending socket IDs:', socketIds);

        // Send the socket IDs back to the client
        socket.emit('user-socket-ids', socketIds);
    });

    socket.on("disconnect", () => {
        if (socket === adminSocket) {
            adminSocket = null;
            console.log("Admin disconnected", socket.id);
        } else {
            for (const [userId, userData] of userSockets.entries()) {
                if (userData.socket === socket) {
                    userSockets.delete(userId);
                    console.log("User disconnected:", userId, socket.id);
                    break;
                }
            }
        }
    });

});

app.get("/", (req, res) => {
    res.send("Express app is running");
});

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token");
    }
};

app.post("/signup", async (req, res) => {
    const { email, username, phoneNumber, password, confirmPassword } = req.body;

    const lowerCaseEmail = email.toLowerCase();

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s]+$/;
    if (!emailRegex.test(lowerCaseEmail)) {
        throw new ApiError(400, "Invalid email format");
    }

    let check = await User.findOne({ email: lowerCaseEmail });
    if (check) {
        throw new ApiError(400, "Email already exists");
    }

    if (password !== confirmPassword) {
        throw new ApiError(400, "Passwords do not match");
    }

    const user = new User({
        username: username,
        email: lowerCaseEmail,
        password: password,
        phoneNumber: phoneNumber
    });

    const savedUser = await user.save();

    if (!savedUser) {
        throw new ApiError(400, "User registration failed");
    } else {
        res.status(200).json(new ApiResponse(200, "User added successfully"));
    }
});

app.post("/login", async (req, res) => {
    const { email, phoneNumber, password } = req.body;

    try {
        let user;

        if (email) {
            const lowerCaseEmail = email.toLowerCase();
            user = await User.findOne({ email: lowerCaseEmail });
        } else if (phoneNumber) {
            user = await User.findOne({ phoneNumber: phoneNumber });
        } else {
            throw new ApiError(400, "Please provide either email or phone number");
        }

        if (!user) {
            throw new ApiError(401, "Invalid credentials");
        }

        if (!user.isActive) {
            throw new ApiError(403, "Your account has been deactivated. Please contact support.");
        }

        const isPasswordValid = await user.isPasswordCorrect(password);

        if (!isPasswordValid) {
            throw new ApiError(401, "Invalid Password");
        }

        const tokens = await generateAccessAndRefreshTokens(user._id);
        console.log("Generated tokens:", tokens); // Debug log

        const { accessToken, refreshToken } = tokens;

        console.log("Access Token:", accessToken); // Debug log
        console.log("Refresh Token:", refreshToken); // Debug log

        const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

        const response = new ApiResponse(
            200,
            { user: loggedInUser, accessToken, refreshToken },
            "User logged in successfully"
        );
        console.log("API Response:", response); // Debug log

        return res
            .status(200)
            .cookie("accessToken", accessToken)
            .cookie("refreshToken", refreshToken) // 7 days
            .json(new ApiResponse(
                200,
                { user: loggedInUser, accessToken, refreshToken },
                "user logged in successfully"
            ));
    } catch (error) {
        console.error(error);
        if (error instanceof ApiError) {
            return res.status(error.statusCode).json(new ApiResponse(error.statusCode, null, error.message));
        }
        return res.status(500).json(new ApiResponse(500, null, "Internal Server Error"));
    }
});

// File upload endpoint
app.post('/api/upload', upload.single('attachment'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const fileUrl = `/uploads/${req.file.filename}`;
        res.json({ fileUrl });
    } catch (error) {
        console.error('Error uploading file:', error);
        res.status(500).json({ error: 'Failed to upload file' });
    }
});

app.get("/users", asyncHandler(async (req, res) => {
    try {
        const users = await User.find({}).select("email phoneNumber username isActive");
        res.status(200).json({
            status: "success",
            data: users
        });
    } catch (error) {
        console.error("Error fetching users:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching users"
        });
    }
}));

app.get("/users/:userId", asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId).select("email phoneNumber username isActive");

        if (!user) {
            return res.status(404).json({
                status: "error",
                message: "User not found"
            });
        }

        res.status(200).json({
            status: "success",
            data: user
        });
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching user"
        });
    }
}));

app.put("/users/:userId/status", asyncHandler(async (req, res) => {
    try {
        const { userId } = req.params;
        const { isActive } = req.body;

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { isActive },
            { new: true, select: "email phoneNumber username isActive" }
        );

        if (!updatedUser) {
            return res.status(404).json({
                status: "error",
                message: "User not found"
            });
        }

        res.status(200).json({
            status: "success",
            message: "User status updated successfully",
            data: updatedUser
        });
    } catch (error) {
        console.error("Error updating user status:", error);
        res.status(500).json({
            status: "error",
            message: "Error updating user status"
        });
    }
}));

app.post("/logout", VerifyJWT, asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: { refreshToken: 1 }
        },
        { new: true }
    );

    const options = {
        httpOnly: true,
        secure: true
    };

    res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out"));
}));

app.post('/api/create-admin', async (req, res) => {
    try {
        const admin = new User({ isAdmin: true, ...req.body });
        await admin.save();
        res.status(201).json({ message: 'Admin created successfully' });
    } catch (error) {
        console.error('Error creating admin:', error);
        res.status(500).json({ error: 'Failed to create admin' });
    }
});

app.get("/api/chat-history", async (req, res) => {
    try {
        const admin = await User.findOne({ role: "admin" });
        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }

        const messages = await Message.find({
            $or: [
                { sender: admin._id },
                { receiver: admin._id }
            ]
        }).sort({ timestamp: 1 });

        res.json(messages);
    } catch (error) {
        console.error("Error fetching chat history:", error);
        res.status(500).json({ message: "Error fetching chat history" });
    }
});

app.post('/api/messages', async (req, res) => {
    console.log("Received message saving request:", req.body);
    try {
        const { sender, receiver, text, messageType, fileUrl } = req.body;

        // Validate ObjectIds for private messages
        if (messageType === 'private') {
            if (!mongoose.Types.ObjectId.isValid(sender) || !mongoose.Types.ObjectId.isValid(receiver)) {
                console.log("Invalid sender or receiver ID");
                return res.status(400).json({ error: 'Invalid sender or receiver ID' });
            }
        }

        // For broadcast messages, receiver must be null
        if (messageType === 'broadcast' && receiver !== null) {
            console.log("Broadcast message should have null receiver");
            return res.status(400).json({ error: 'Broadcast message should have null receiver' });
        }

        // Validate messageType
        if (!['broadcast', 'private'].includes(messageType)) {
            console.log("Invalid message type");
            return res.status(400).json({ error: 'Invalid message type' });
        }

        const savedMessage = await saveMessage(sender, receiver, text, messageType, fileUrl);
        console.log("Message saved successfully:", savedMessage);
        res.status(201).json({ message: 'Message saved successfully', data: savedMessage });
    } catch (error) {
        console.error('Error saving message:', error);
        res.status(500).json({ error: 'Failed to save message', details: error.message });
    }
});

// Fetch broadcast messages
app.get("/api/chat-history/broadcast", async (req, res) => {
    try {
        const messages = await Message.find({ messageType: 'broadcast' }).sort({ timestamp: 1 });
        res.json(messages);
    } catch (error) {
        console.error("Error fetching broadcast chat history:", error);
        res.status(500).json({ message: "Error fetching broadcast chat history" });
    }
});

// Fetch private messages for a specific user
app.get("/api/chat-history/private/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        // Ensure that userId is valid
        if (!userId) {
            return res.status(400).json({ message: "Invalid user ID" });
        }

        // Find the admin user
        const admin = await User.findOne({ role: "admin" });
        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }

        // Fetch messages between the user and admin
        const messages = await Message.find({
            $or: [
                { sender: userId, receiver: admin._id },
                { sender: admin._id, receiver: userId }
            ],
            messageType: 'private'
        }).sort({ timestamp: 1 });

        // Return messages
        res.json(messages);
    } catch (error) {
        console.error("Error fetching private chat history:", error);
        res.status(500).json({ message: "Error fetching private chat history" });
    }
});

app.delete("/api/chat-history/broadcast", async (req, res) => {
    try {
        const result = await Message.deleteMany({ messageType: 'broadcast' });
        console.log(`Deleted ${result.deletedCount} broadcast messages`);
        res.status(200).json({ message: "Broadcast chat history deleted", deletedCount: result.deletedCount });
    } catch (error) {
        console.error("Error deleting broadcast chat history:", error);
        res.status(500).json({ message: "Error deleting broadcast chat history" });
    }
});

// Delete private messages for a specific user
app.delete("/api/chat-history/private/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        const admin = await User.findOne({ role: "admin" });
        if (!admin) {
            return res.status(404).json({ message: "Admin not found" });
        }

        await Message.deleteMany({
            $or: [
                { sender: userId, receiver: admin._id },
                { sender: admin._id, receiver: userId }
            ],
            messageType: 'private'
        });

        res.status(200).json({ message: "Private chat history deleted for the specified user" });
    } catch (error) {
        console.error("Error deleting private chat history:", error);
        res.status(500).json({ message: "Error deleting private chat history" });
    }
});

// Endpoint to toggle chat status
app.post('/api/toggle-chats', async (req, res) => {
    const { isDeactivated } = req.body;

    try {
        // Update chat status in the database
        await ChatStatus.findOneAndUpdate({}, { isDeactivated }, { upsert: true });
        io.emit('chat-deactivation-status', { isDeactivated }); // Notify all connected users
        res.status(200).send({ message: isDeactivated ? "All chats have been deactivated" : "All chats have been reactivated" });
    } catch (error) {
        console.error("Error toggling chats:", error);
        res.status(500).send({ error: isDeactivated ? "Failed to deactivate chats" : "Failed to reactivate chats" });
    }
});

// Endpoint to get chat deactivation status
app.get('/api/chat-deactivation-status', async (req, res) => {
    try {
        const status = await ChatStatus.findOne({});
        res.status(200).send({ isDeactivated: status ? status.isDeactivated : false });
    } catch (error) {
        console.error("Error fetching chat deactivation status:", error);
        res.status(500).send({ error: "Failed to fetch chat deactivation status" });
    }
});

// Endpoint to toggle user chat status
app.put('/api/toggle-user-chat/:userId', async (req, res) => {
    const { userId } = req.params;
    const { isChatActive } = req.body;

    try {
        // Update chat status in the database
        await User.findByIdAndUpdate(userId, { isChatActive });

        // Notify connected clients
        io.emit('admin-toggle-user-chat', { userId, isChatActive });

        res.status(200).send({ message: isChatActive ? "Chat reactivated" : "Chat deactivated" });
    } catch (error) {
        console.error("Error toggling user chat status:", error);
        res.status(500).send({ error: "Failed to toggle user chat status" });
    }
});

app.put('/users/:userId/status', async (req, res) => {
    const { userId } = req.params;
    const { isActive } = req.body;

    try {
        // Validate isActive is a boolean
        if (typeof isActive !== 'boolean') {
            return res.status(400).send({ error: "isActive must be a boolean" });
        }

        // Update the user's status in the database
        const user = await User.findByIdAndUpdate(userId, { isActive }, { new: true });

        if (!user) {
            return res.status(404).send({ error: "User not found" });
        }

        // Notify all connected clients about the status change
        io.emit('admin-toggle-user-status', { userId, isActive });

        res.status(200).send({ message: isActive ? "User reactivated" : "User deactivated" });
    } catch (error) {
        console.error("Error toggling user status:", error);
        res.status(500).send({ error: "Failed to toggle user status" });
    }
});

// stock data 
app.post('/calculate', async (req, res) => {
    const { userId, strikeName, quantity, buyPrice, sellPrice, charges, brokerage } = req.body;

    // Convert values to numbers
    const buy = parseFloat(buyPrice);
    const sell = parseFloat(sellPrice);
    const qty = parseFloat(quantity);
    const charge = parseFloat(charges);
    const broker = parseFloat(brokerage);

    // Calculate total cost, revenue, and net profit/loss
    const totalCost = (buy * qty) + charge + broker;
    const totalRevenue = sell * qty;
    const netProfitLoss = totalRevenue - totalCost;

    // Prepare the result object
    const result = {
        userId, // Include userId in the result
        strikeName,
        quantity: qty,
        buyPrice: buy,
        sellPrice: sell,
        charges: charge,
        brokerage: broker,
        profit: null,
        loss: null,
    };

    // Determine if it's a profit or loss
    if (netProfitLoss > 0) {
        result.profit = netProfitLoss;
    } else {
        result.loss = Math.abs(netProfitLoss);
    }

    // Save the result to the database
    try {
        // Create and save the stock trade
        const stockTrade = new StockTrade(result);
        const savedTrade = await stockTrade.save();

        // Update the user's trade list
        await User.findByIdAndUpdate(userId, { $push: { trades: savedTrade._id } });

        // Respond with the result
        res.status(201).json(result);
    } catch (error) {
        console.error('Error saving to database:', error);
        res.status(500).json({ error: 'Error saving to database' });
    }
});

app.get('/trades', async (req, res) => {
    try {
        const trades = await StockTrade.find();
        res.json(trades);
    } catch (error) {
        console.error('Error fetching trades:', error);
        res.status(500).json({ error: 'Error fetching trades' });
    }
});

app.get('/userTrades/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const trades = await StockTrade.find({ userId });
        res.json(trades);
    } catch (error) {
        console.error('Error fetching trades:', error);
        res.status(500).json({ error: 'Error fetching trades' });
    }
});

// PUT endpoint to update a trade
app.put('/userTrades/:userId', async (req, res) => {
    const { userId } = req.params;
    const { strikeName, quantity, buyPrice, sellPrice, charges, brokerage, profit, loss } = req.body;

    try {
        // Find the trade by ID and update it
        const updatedTrade = await StockTrade.findByIdAndUpdate(
            userId,
            { strikeName, quantity, buyPrice, sellPrice, charges, brokerage, profit, loss },
            { new: true, runValidators: true } // Return the updated document and validate input
        );

        if (!updatedTrade) {
            return res.status(404).json({ error: 'Trade not found' });
        }

        res.json(updatedTrade);
    } catch (error) {
        console.error('Error updating trade:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/allUserTrades', async (req, res) => {
    try {
        const usersWithTrades = await User.find({})
            .populate({
                path: 'trades',
                select: 'strikeName quantity buyPrice sellPrice charges brokerage profit loss createdAt' // Select fields to display
            })
            .select('username email phoneNumber trades');

        res.status(200).json({
            status: "success",
            data: usersWithTrades
        });
    } catch (error) {
        console.error('Error fetching users with trades:', error);
        res.status(500).json({ error: 'Error fetching users with trades' });
    }
});

app.put('/updateDailyCharges', async (req, res) => {
    const { userId, date, charges } = req.body;

    try {
        // Find all trades for the user on the specified date
        const trades = await StockTrade.find({
            userId,
            createdAt: {
                $gte: new Date(date),
                $lt: new Date(date).setDate(new Date(date).getDate() + 1)
            }
        });

        if (trades.length === 0) {
            return res.status(404).json({ error: 'No trades found for the specified date' });
        }

        // Check if daily charges have already been updated
        if (trades.some(trade => trade.dailyChargesUpdated)) {
            return res.status(400).json({ error: 'Daily charges have already been updated for this date' });
        }

        // Calculate the charges per trade
        const chargesPerTrade = parseFloat(charges) / trades.length;

        // Update each trade with the new charges, recalculate profit/loss, and mark as updated
        const updatedTrades = await Promise.all(trades.map(async (trade) => {
            const newCharges = chargesPerTrade;
            const totalCost = (trade.buyPrice * trade.quantity) + newCharges + trade.brokerage;
            const totalRevenue = trade.sellPrice * trade.quantity;
            const netProfitLoss = totalRevenue - totalCost;

            const updatedTrade = await StockTrade.findByIdAndUpdate(
                trade._id,
                {
                    charges: newCharges,
                    profit: netProfitLoss > 0 ? netProfitLoss : 0,
                    loss: netProfitLoss < 0 ? Math.abs(netProfitLoss) : 0,
                    dailyChargesUpdated: true
                },
                { new: true }
            );

            return updatedTrade;
        }));

        // Fetch all updated trades for the user
        const allUpdatedTrades = await StockTrade.find({ userId });

        res.json(allUpdatedTrades);
    } catch (error) {
        console.error('Error updating daily charges:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/updateDailyChargesForAllUsers', async (req, res) => {
    const { date, charges } = req.body;

    // Input validation
    if (!date || isNaN(Date.parse(date)) || isNaN(parseFloat(charges))) {
        return res.status(400).json({ error: 'Valid date and numeric charges are required' });
    }

    try {
        // Parse date and set time boundaries for the day
        const startOfDay = new Date(date);
        const endOfDay = new Date(startOfDay);
        endOfDay.setDate(startOfDay.getDate() + 1);

        // Find all trades on the specified date
        const trades = await StockTrade.find({
            createdAt: {
                $gte: startOfDay,
                $lt: endOfDay
            }
        });

        if (trades.length === 0) {
            return res.status(404).json({ error: 'No trades found for the specified date' });
        }

        // Calculate charges per trade
        const totalTrades = trades.length;
        const chargesPerTrade = parseFloat(charges) / totalTrades;

        // Update each trade with the new charges and recalculate profit/loss
        const updatedTrades = await Promise.all(trades.map(async (trade) => {
            const newCharges = chargesPerTrade;
            const totalCost = (trade.buyPrice * trade.quantity) + newCharges + trade.brokerage;
            const totalRevenue = trade.sellPrice * trade.quantity;
            const netProfitLoss = totalRevenue - totalCost;

            const updatedTrade = await StockTrade.findByIdAndUpdate(
                trade._id,
                {
                    charges: newCharges,
                    profit: netProfitLoss > 0 ? netProfitLoss : 0,
                    loss: netProfitLoss < 0 ? Math.abs(netProfitLoss) : 0,
                    dailyChargesUpdated: true // Mark as updated
                },
                { new: true }
            );

            return updatedTrade;
        }));

        // Fetch all updated trades
        const allUpdatedTrades = await StockTrade.find({
            createdAt: {
                $gte: startOfDay,
                $lt: endOfDay
            }
        });

        res.status(200).json({
            status: "success",
            message: `Updated charges for ${allUpdatedTrades.length} trades on ${date}`,
            data: allUpdatedTrades
        });
    } catch (error) {
        console.error('Error updating daily charges for all users:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// courses

app.post("/api/courses", async (req, res) => {
    try {
        const { courseName, price, expiryDate, validityPeriod } = req.body;

        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        if (!courseName || !price || !expiryDate || !validityPeriod) {
            return res.status(400).json({
                status: "error",
                message: "Course name, price, expiry date, and validity period are required"
            });
        }

        const expiry = new Date(expiryDate);
        if (isNaN(expiry.getTime()) || expiry < new Date()) {
            return res.status(400).json({
                status: "error",
                message: "Invalid expiry date. Date must be in the future."
            });
        }

        // Validate validity period
        if (!validityPeriod.duration || !validityPeriod.unit) {
            return res.status(400).json({
                status: "error",
                message: "Invalid validity period"
            });
        }

        const course = new Course({
            courseName,
            price: parseFloat(price),
            expiryDate: expiry,
            validityPeriod,
            createdBy: admin,
            status: 'draft',
            content: []
        });

        const savedCourse = await course.save();

        res.status(201).json({
            status: "success",
            data: savedCourse,
            courseId: course._id,
            message: "Course created successfully"
        });

    } catch (error) {
        console.error("Error creating course:", error);
        res.status(500).json({
            status: "error",
            message: "Error creating course"
        });
    }
});

app.get("/api/courses", async (req, res) => {
    try {
        const courses = await Course.find()
            .select('courseName price status expiryDate validityPeriod') // Added expiryDate to selection
            .sort({ createdAt: -1 });

        res.status(200).json({
            status: "success",
            data: courses
        });
    } catch (error) {
        console.error("Error fetching courses:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching courses"
        });
    }
});


app.post("/api/courses/:courseId/content",
    upload.fields([
        { name: 'thumbnail', maxCount: 1 },
        { name: 'video', maxCount: 1 }
    ]),
    async (req, res) => {
        try {
            const { courseId } = req.params;
            const { title, description } = req.body;

            const admin = await User.findOne({ role: 'admin' });
            if (!admin) {
                return res.status(403).json({
                    status: "error",
                    message: "Unauthorized access"
                });
            }

            const course = await Course.findById(courseId);
            if (!course) {
                return res.status(404).json({
                    status: "error",
                    message: "Course not found"
                });
            }

            // Upload files to Cloudinary
            let thumbnailUrl, videoUrl;
            try {
                // Extract just the secure_url from the Cloudinary response
                const thumbnailResponse = req.files.thumbnail && req.files.thumbnail.length > 0
                    ? await uploadOnCloudinary(req.files.thumbnail[0])
                    : undefined;
                thumbnailUrl = thumbnailResponse?.secure_url;

                const videoResponse = req.files.video && req.files.video.length > 0
                    ? await uploadOnCloudinary(req.files.video[0])
                    : undefined;
                videoUrl = videoResponse?.secure_url;

                if (!thumbnailUrl || !videoUrl) {
                    return res.status(400).json({
                        status: "error",
                        message: "Both thumbnail and video are required"
                    });
                }
            } catch (uploadError) {
                console.error("Error uploading files to Cloudinary:", uploadError);
                return res.status(500).json({
                    status: "error",
                    message: "Error uploading files to Cloudinary",
                    error: uploadError.message
                });
            }

            const newContent = {
                title,
                description,
                thumbnailUrl,  // Now this will be just the URL string
                videoUrl,      // Now this will be just the URL string
            };

            // Ensure content array is initialized before pushing
            if (!course.content) course.content = [];
            course.content.push(newContent);
            course.status = 'published';

            await course.save();

            res.status(201).json({
                status: "success",
                data: course,
                message: "Course content added successfully"
            });

        } catch (error) {
            console.error("Error adding course content:", error);
            res.status(500).json({
                status: "error",
                message: "Error adding course content",
                error: error.message
            });
        }
    }
);

app.put("/api/courses/:courseId", async (req, res) => {
    try {
        const { courseId } = req.params;
        const { courseName, price, expiryDate, validityPeriod } = req.body;

        // Validate admin access
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        // Input validation
        if (!courseName || !price || !expiryDate || !validityPeriod) {
            return res.status(400).json({
                status: "error",
                message: "Course name, price, expiry date, and validity period are required"
            });
        }

        if (isNaN(price) || parseFloat(price) < 0) {
            return res.status(400).json({
                status: "error",
                message: "Invalid price format"
            });
        }

        // Validate expiry date
        const expiryDateObj = new Date(expiryDate);
        if (isNaN(expiryDateObj.getTime())) {
            return res.status(400).json({
                status: "error",
                message: "Invalid expiry date format"
            });
        }

        // Validate validity period
        if (!validityPeriod.duration || !validityPeriod.unit ||
            !["days", "months", "years"].includes(validityPeriod.unit) ||
            parseInt(validityPeriod.duration) <= 0) {
            return res.status(400).json({
                status: "error",
                message: "Invalid validity period"
            });
        }

        // Update course
        const updatedCourse = await Course.findByIdAndUpdate(
            courseId,
            {
                courseName,
                price: parseFloat(price),
                expiryDate: expiryDateObj,
                validityPeriod: {
                    duration: parseInt(validityPeriod.duration),
                    unit: validityPeriod.unit
                }
            },
            { new: true }
        );

        if (!updatedCourse) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        res.status(200).json({
            status: "success",
            data: updatedCourse,
            message: "Course updated successfully"
        });

    } catch (error) {
        console.error("Error updating course:", error);
        res.status(500).json({
            status: "error",
            message: "Error updating course"
        });
    }
});

app.get("/api/courses/:courseId", async (req, res) => {
    try {
        const course = await Course.findById(req.params.courseId);

        if (!course) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        res.status(200).json({
            status: "success",
            data: course,
            message: "Course details retrieved successfully"
        });
    } catch (error) {
        console.error("Error fetching course details:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching course details"
        });
    }
});

app.post("/api/courses/:courseId/purchase", VerifyJWT, async (req, res) => {
    try {
        const { courseId } = req.params;
        const userId = req.user._id;

        const existingPurchase = await Purchase.findOne({
            user: userId,
            course: courseId,
            status: 'completed'
        });

        if (existingPurchase) {
            return res.status(400).json({
                status: "error",
                message: "Course already purchased"
            });
        }

        const purchaseDate = new Date();
        const expiryDate = new Date(purchaseDate);

        const purchase = new Purchase({
            user: userId,
            course: courseId,
            purchaseDate,
            expiryDate,
            status: 'completed'
        });

        await purchase.save();

        res.status(200).json({
            status: "success",
            data: purchase,
            message: "Course purchased successfully"
        });

    } catch (error) {
        console.error("Error purchasing course:", error);
        res.status(500).json({
            status: "error",
            message: "Error purchasing course"
        });
    }
});

// Get user's purchased courses
app.get("/api/users/purchases", VerifyJWT, async (req, res) => {
    try {
        const userId = req.user._id;

        // Fetch purchases with the latest course data
        const purchases = await Purchase.find({ user: userId })
            .populate('course', 'courseName price validityPeriod isActive content')
            .sort({ purchaseDate: -1 });

        const purchasesWithValidity = purchases.map(purchase => {
            try {
                const purchaseObj = purchase.toObject();

                // Ensure we're using the latest validityPeriod from the course
                console.log('Fetched validityPeriod:', purchaseObj.course?.validityPeriod);

                // Calculate expiry date based on the latest validityPeriod
                const validityExpiryDate = calculateExpiryDate(
                    purchaseObj.purchaseDate,
                    purchaseObj.course?.validityPeriod || { unit: 'years', duration: 1 }
                );

                // Determine if the purchase is expired and update isActive status
                const isExpired = validityExpiryDate < new Date();
                const isActive = !isExpired && purchaseObj.course?.isActive;

                return {
                    ...purchaseObj,
                    validityExpiryDate,
                    accessStatus: {
                        isExpired,
                        isActive,
                        remainingDays: isExpired ? 0 :
                            Math.ceil((validityExpiryDate - new Date()) / (1000 * 60 * 60 * 24))
                    }
                };
            } catch (error) {
                console.error('Error processing purchase:', error);

                // Default validity if calculation fails
                const defaultExpiry = new Date();
                defaultExpiry.setFullYear(defaultExpiry.getFullYear() + 1);

                return {
                    ...purchase.toObject(),
                    validityExpiryDate: defaultExpiry,
                    accessStatus: {
                        isExpired: false,
                        isActive: purchase.course?.isActive ?? true,
                        remainingDays: 365
                    }
                };
            }
        });

        res.status(200).json({
            status: "success",
            data: purchasesWithValidity
        });

    } catch (error) {
        console.error("Error fetching purchased courses:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching purchased courses"
        });
    }
});


// Delete entire course
app.delete("/api/courses/:courseId", async (req, res) => {
    try {
        const { courseId } = req.params;

        // Validate admin access
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        // Find the course first to get its content
        const course = await Course.findById(courseId);
        if (!course) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        // Delete associated files from Cloudinary
        for (const content of course.content) {
            if (content.thumbnailUrl) {
                const publicId = content.thumbnailUrl.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(publicId);
            }
            if (content.videoUrl) {
                const publicId = content.videoUrl.split('/').pop().split('.')[0];
                await cloudinary.uploader.destroy(publicId);
            }
        }

        // Delete the course
        await Course.findByIdAndDelete(courseId);
        await Course.findByIdAndUpdate(courseId, { isDeleted: true });

        res.status(200).json({
            status: "success",
            message: "Course and associated content deleted successfully"
        });

    } catch (error) {
        console.error("Error deleting course:", error);
        res.status(500).json({
            status: "error",
            message: "Error deleting course"
        });
    }
});

// Delete specific course content
app.delete("/api/courses/:courseId/content/:contentId", async (req, res) => {
    try {
        const { courseId, contentId } = req.params;

        // Validate admin access
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        // Find the course
        const course = await Course.findById(courseId);
        if (!course) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        // Find the content item
        const contentItem = course.content.id(contentId);
        if (!contentItem) {
            return res.status(404).json({
                status: "error",
                message: "Content not found"
            });
        }

        // Delete files from Cloudinary
        if (contentItem.thumbnailUrl) {
            const publicId = contentItem.thumbnailUrl.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(publicId);
        }
        if (contentItem.videoUrl) {
            const publicId = contentItem.videoUrl.split('/').pop().split('.')[0];
            await cloudinary.uploader.destroy(publicId);
        }

        // Remove the content from the course
        course.content.pull(contentId);

        // Update course status if no content remains
        if (course.content.length === 0) {
            course.status = 'draft';
        }

        await course.save();

        res.status(200).json({
            status: "success",
            message: "Course content deleted successfully"
        });

    } catch (error) {
        console.error("Error deleting course content:", error);
        res.status(500).json({
            status: "error",
            message: "Error deleting course content"
        });
    }
});

app.get("/api/admin/purchases", async (req, res) => {
    try {
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        const {
            page = 1,
            limit = 10,
            sortBy = 'purchaseDate',
            sortOrder = 'desc',
            username,
            courseName,
            status
        } = req.query;

        const filter = {};
        if (status) {
            filter.status = status;
        }

        let query = Purchase.find(filter);

        query = query.populate({
            path: 'user',
            select: 'username email',
            match: username ? { username: new RegExp(username, 'i') } : {}
        }).populate({
            path: 'course',
            select: 'courseName price validityPeriod isActive',
            match: courseName ? { courseName: new RegExp(courseName, 'i') } : {}
        });

        const sortDirection = sortOrder === 'desc' ? -1 : 1;
        query = query.sort({ [sortBy]: sortDirection });

        const skip = (parseInt(page) - 1) * parseInt(limit);
        query = query.skip(skip).limit(parseInt(limit));

        const purchases = await query.exec();

        // Calculate expiry date for each purchase with error handling
        const purchasesWithExpiry = purchases
            .filter(purchase => purchase.user && purchase.course)
            .map(purchase => {
                try {
                    const purchaseObj = purchase.toObject();
                    return {
                        ...purchaseObj,
                        validityExpiryDate: calculateExpiryDate(
                            purchaseObj.purchaseDate,
                            purchaseObj.course?.validityPeriod || { unit: 'years', duration: 1 }
                        )
                    };
                } catch (error) {
                    console.error('Error processing purchase:', error);
                    // Return purchase with default expiry date
                    const defaultExpiry = new Date(purchase.purchaseDate);
                    defaultExpiry.setFullYear(defaultExpiry.getFullYear() + 1);

                    return {
                        ...purchase.toObject(),
                        validityExpiryDate: defaultExpiry
                    };
                }
            });

        const totalCount = await Purchase.countDocuments(filter);

        res.status(200).json({
            status: "success",
            data: purchasesWithExpiry,
            pagination: {
                currentPage: parseInt(page),
                totalPages: Math.ceil(totalCount / parseInt(limit)),
                totalItems: totalCount,
                itemsPerPage: parseInt(limit)
            }
        });

    } catch (error) {
        console.error("Error fetching all purchases:", error);
        res.status(500).json({
            status: "error",
            message: "Error fetching purchases"
        });
    }
});

app.patch('/api/admin/purchases/:courseId/toggle-status', async (req, res) => {
    try {
        // Verify admin access
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        const { courseId } = req.params;
        const { isActive } = req.body;

        const course = await Course.findByIdAndUpdate(
            courseId,
            { isActive },
            { new: true }
        );

        if (!course) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        res.status(200).json({
            status: "success",
            data: course
        });

    } catch (error) {
        console.error("Error toggling course status:", error);
        res.status(500).json({
            status: "error",
            message: "Error updating course status"
        });
    }
});

app.patch('/api/admin/purchases/toggle-all-status', async (req, res) => {
    try {
        // Verify admin access
        const admin = await User.findOne({ role: 'admin' });
        if (!admin) {
            return res.status(403).json({
                status: "error",
                message: "Unauthorized access"
            });
        }

        const { isActive } = req.body;

        await Course.updateMany(
            {},
            { isActive }
        );

        res.status(200).json({
            status: "success",
            message: `All courses ${isActive ? 'activated' : 'deactivated'} successfully`
        });

    } catch (error) {
        console.error("Error toggling all courses status:", error);
        res.status(500).json({
            status: "error",
            message: "Error updating courses status"
        });
    }
});





export { app, io };