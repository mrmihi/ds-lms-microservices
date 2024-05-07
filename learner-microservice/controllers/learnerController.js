const express = require("express");
const router = express.Router();
const Learner = require("../models/learnerSchema");

// Enroll course
router.post("/course/enroll", async (req, res) => {
  try {
    const { learnerId } = req.body;
    const courseId = req.query.courseId;

    if (!courseId) {
      return res.status(400).json({ error: "Course ID is required" });
    }

    // Check if the exist
    const learner = await Learner.findById(learnerId);

    if (!learner) {
      return res.status(404).json({ error: "Learner not found" });
    }

    // Check if the learner is already enrolled in the course
    if (learner.enrolledCourses.includes(courseId)) {
      return res
        .status(400)
        .json({ error: "Learner is already enrolled in this course" });
    }

    // Add the course to the learner's enrolledCourses array
    learner.enrolledCourses.push(courseId);
    await learner.save();

    res.status(200).json({ message: "Student enrolled successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
