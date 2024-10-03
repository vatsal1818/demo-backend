import { ApiError } from "../utils/ApiErrors.js";
import { asyncHandler } from "../utils/AsynceHandler.js";
import jwt from "jsonwebtoken";
import { User } from "../models/User.models.js";

export const VerifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "").trim();

        if (!token) {
            return res.status(401).json(new ApiError(401, "Unauthorized request"));
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        if (!decodedToken?._id) {
            return res.status(401).json(new ApiError(401, "Invalid access token"));
        }

        const user = await User.findById(decodedToken._id).select("-password -refreshToken");

        if (!user) {
            return res.status(401).json(new ApiError(401, "User not found"));
        }

        req.user = user;
        next();

    } catch (error) {
        console.error("Token verification error:", error);
        return res.status(401).json(new ApiError(401, error.message || "Invalid access token"));
    }
});
