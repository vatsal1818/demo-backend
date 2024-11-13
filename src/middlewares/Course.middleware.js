export const checkCourseAccess = async (req, res, next) => {
    try {
        const { courseId } = req.params;
        const userId = req.user._id;

        const course = await Course.findById(courseId);
        if (!course) {
            return res.status(404).json({
                status: "error",
                message: "Course not found"
            });
        }

        if (!course.hasValidAccess(userId)) {
            return res.status(403).json({
                status: "error",
                message: "You don't have active access to this course"
            });
        }

        req.course = course;
        next();
    } catch (error) {
        console.error("Error checking course access:", error);
        res.status(500).json({
            status: "error",
            message: "Error checking course access"
        });
    }
};