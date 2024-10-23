import { v2 as cloudinary } from "cloudinary";
import fs from "fs";
import dotenv from 'dotenv';
import path from 'path';

dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

const ALLOWED_IMAGE_TYPES = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
const ALLOWED_VIDEO_TYPES = ['.mp4', '.mov', '.avi', '.webm'];

const detectFileType = (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    if (ALLOWED_IMAGE_TYPES.includes(ext)) return "image";
    if (ALLOWED_VIDEO_TYPES.includes(ext)) return "video";
    return null; // Return null instead of throwing error for more graceful handling
};

const validateFile = (filePath, type) => {
    const ext = path.extname(filePath).toLowerCase();
    const allowedTypes = type === "video" ? ALLOWED_VIDEO_TYPES : ALLOWED_IMAGE_TYPES;

    if (!allowedTypes.includes(ext)) {
        console.log(`File validation failed: ${ext} not in allowed types for ${type}`);
        return false;
    }

    try {
        const stats = fs.statSync(filePath);
        const fileSizeInMB = stats.size / (1024 * 1024);

        if (type === "video" && fileSizeInMB > 100) {
            console.log(`File validation failed: Video size ${fileSizeInMB}MB exceeds 100MB limit`);
            return false;
        } else if (type === "image" && fileSizeInMB > 10) {
            console.log(`File validation failed: Image size ${fileSizeInMB}MB exceeds 10MB limit`);
            return false;
        }

        return true;
    } catch (error) {
        console.error("Error validating file:", error);
        return false;
    }
};

const uploadOnCloudinary = async (file) => {
    let filePath = null;
    let uploadResult = null;

    try {
        if (!file) {
            console.log("Upload aborted: No file provided");
            return null;
        }

        filePath = file.path;
        console.log("\n=== Starting upload process ===");
        console.log("Input file details:", {
            originalName: file.originalname,
            path: filePath,
            mimeType: file.mimetype,
            size: file.size ? `${(file.size / (1024 * 1024)).toFixed(2)}MB` : 'Unknown'
        });

        // File existence check
        if (!fs.existsSync(filePath)) {
            console.log(`Upload aborted: File not found at ${filePath}`);
            return null;
        }

        // Detect file type
        const type = detectFileType(filePath);
        console.log(`Detected file type: ${type}`);
        if (!type) {
            console.log(`Upload aborted: Unsupported file type for ${file.originalname}`);
            return null;
        }

        // Validation
        if (!validateFile(filePath, type)) {
            console.log(`Upload aborted: File validation failed for ${file.originalname}`);
            return null;
        }

        // Prepare upload options for Cloudinary
        const uploadOptions = {
            resource_type: type === "video" ? "video" : "image",
            folder: type === "video" ? "course_videos" : "course_thumbnails",
            ...(type === "video" ? {
                chunk_size: 6000000,
                eager: [{ format: 'mp4', quality: 'auto' }],
                eager_async: true
            } : {
                transformation: [
                    { width: 1280, height: 720, crop: "fill", quality: "auto" }
                ]
            })
        };

        console.log("Starting Cloudinary upload with options:", uploadOptions);

        // Upload to Cloudinary
        uploadResult = await cloudinary.uploader.upload(filePath, uploadOptions);
        console.log("Upload successful:", {
            publicId: uploadResult.public_id,
            url: uploadResult.secure_url,
            resourceType: uploadResult.resource_type
        });



        return uploadResult;

    } catch (error) {
        console.error("\n=== Upload Error Details ===");
        console.error("Error type:", error.name);
        console.error("Error message:", error.message);
        console.error("HTTP code:", error.http_code || 'N/A');
        console.error("File info:", {
            name: file?.originalname,
            path: filePath,
            type: file?.mimetype
        });

        if (uploadResult) {
            console.error("Error occurred after successful upload. Upload result:", uploadResult);
        }

        throw new Error(`Upload failed: ${error.message}`);

    } finally {
        // Cleanup temporary file
        if (filePath && fs.existsSync(filePath)) {
            try {
                fs.unlinkSync(filePath);
                console.log("Cleanup: Successfully removed temporary file:", filePath);
            } catch (unlinkError) {
                console.error("Cleanup: Failed to remove temporary file:", {
                    path: filePath,
                    error: unlinkError.message
                });
            }
        }
        console.log("=== Upload process complete ===\n");
    }
};


export { uploadOnCloudinary };