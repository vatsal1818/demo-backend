import multer from 'multer';
import path from 'path';
import fs from 'fs';

// Ensure uploads directory exists
const uploadDir = 'uploads/';
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname)
    }
});

// File filter to validate uploads
const fileFilter = (req, file, cb) => {
    if (file.fieldname === "thumbnail") {
        // Accept only image files for thumbnail
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only image files are allowed for thumbnail!'), false);
        }
    } else if (file.fieldname === "video") {
        // Accept only video files for video
        if (!file.mimetype.startsWith('video/')) {
            return cb(new Error('Only video files are allowed for video!'), false);
        }
    }
    cb(null, true);
};

const upload = multer({ storage, fileFilter });

export default upload;
