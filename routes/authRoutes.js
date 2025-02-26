const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
require('dotenv').config();

const router = express.Router()

// **REGISTER USER** SIGNUP
router.post("/register", async (req, res) => {
    try{
        const {username, email, password, role} = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({username, email, password: hashedPassword, role});
        
        await user.save();

        res.status(201).json({message: "User Registered Successfully"})
    }

    catch(error){
        res.status(500).json({message: "Error Registering the user", error})
    }
});


// **LOGIN USER** 
router.post("/login", async (req, res) => {
    try {
        console.log("📩 Request received:", req.body); // Log incoming data

        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            console.log("❌ User not found in DB");
            return res.status(401).json({ message: "User not found" });
        }

        console.log("✅ User found:", user);

        const isMatch = await bcrypt.compare(password, user.password);
        console.log("🔑 Password match status:", isMatch); // Log match result

        if (!isMatch) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign(
            { userId: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        console.log("✅ Token generated:", token);

        res.json({ message: "Login successful", token });
    } catch (error) {
        console.error("🚨 Error:", error);
        res.status(500).json({ message: "Error logging in", error: error.message });
    }
});


module.exports = router;
