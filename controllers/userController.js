const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

// Generate token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" })
};

// Register user
const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please complete all fields")
    }
    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must contain at least 6 characters")
    }

    // Check if user email already exists
    const userExists = await User.findOne({ email })

    if (userExists) {
        res.status(400)
        throw new Error("This email has already been used")
    }

    // Create a new user
    const user = await User.create({
        name,
        email,
        password,
    });

    // Register token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 DAY
        sameSite: "none",
        secure: true
    });

    if (user) {
        const { _id, name, email, picture, phone, bio, token } = user;
        res.status(201).json({
            _id, name, email, picture, phone, bio, token

        });
    } else {
        res.status(400)
        throw new Error("Invalid user data")
    }
});

// Login user
const loginUser = asyncHandler(async (req, res,) => {
    const { email, password } = req.body;

    // Validate request
    if (!email || !password) {
        res.status(400);
        throw new Error("Please add an email and a password")
    }

    // Check if the user exists
    const user = await User.findOne({ email });

    if (!user) {
        res.status(400);
        throw new Error("User not found, please signup");
    }

    // If the user exists, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    // Generate Token
    const token = generateToken(user._id);

    if (passwordIsCorrect) {
        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 + 86400), // 1 day
            sameSite: "none",
            secure: true,
        });
    }
    if (user && passwordIsCorrect) {
        const { _id, name, email, picture, phone, bio } = user;
        res.status(200).json({
            _id,
            name,
            email,
            picture,
            phone,
            bio,
            token,
        });

    } else {
        req.status(400);
        throw new Error("Invalid email or password")
    }
});

// Logout user
const logoutUser = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true
    });
    return res.status(200).json({ message: "Successfully logged out" })
})

// Get user data
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, picture, phone, bio } = user;
        req.status(200).json({
            _id,
            name,
            email,
            picture,
            phone,
            bio,
        });
    } else {
        res.status(400);
        throw new Error("User not found");
    }
});

// Get login status
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;

    if (!token) {
        return res.json(false)
    }
    // Verify token
    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
        return res.json(true)
    }
    return res.json(false)
});

// Update User
const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { name, email, picture, phone, bio } = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;
        user.picture = req.body.picture || picture;

        const updatedUser = await user.save();
        res.status(200).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            picture: updatedUser.picture,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
        });
    } else {
        res.status(404);
        throw new Error("User not found");
    }
});

// Change password
const changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    const { oldPassword, password } = req.body

    // Check if the user is logged in
    if (!user) {
        res.status(400);
        throw new Error("User not found, please sign up")
    }

    // Validate
    if (!oldPassword || !password) {
        res.status(400);
        throw new Error("Please add your old and new passwords")
    }

    // Check if the old password matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password
        await user.save()
        res.status(200).send("Password change successfully")
    } else {
        res.status(400);
        throw new Error("Old password is incorrect")
    }
});

// Forgot password
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email })

    if (!user) {
        res.status(404);
        throw new Error("User does not exist")
    }

    // Delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne()
    }

    // Create a reset token
    let resetToken = crypto.randomBytes(32).toString("hex") + user._id;
    console.log(resetToken)

    // Hash token before saving to the DB
    const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex");

    // Save token to DB
    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000) // Thirty minutes
    }).save()

    // Build a reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetpassword/${resetToken}`

    // Format the reset email
    const message = `
    <h2>hello ${user.name}</h2>
    <p>Please use the link below to reset your password</p>
    <p>This link is valid for only 30 minutes</p>

    <a href="${resetUrl}" clickTracking=off>${resetUrl}</a>

    <p>Regards<p>
    <p>Pinvent Team<p>
`;

    const subject = "Password Reset Request - Pinvent";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;

    try {
        await sendEmail(subject, message, send_to, sent_from)
        res.status(200).json({ success: true, message: "Reset Email Sent" })
    } catch (error) {
        res.status(500)
        throw new Error("Reset email not sent, please try again")
    }
});

// Reset password
const resetPassword = asyncHandler(async (req, res) => {
    const { password } = req.body
    const { resetToken } = req.params

    // Hash token and then compare to Token in the DB
    const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    // Find token in the DB
    const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: { $gt: Date.now() }
    })

    if (!userToken) {
        res.status(404);
        throw new Error("invalid or expire token")
    }

    // Find user
    const user = await User.findOne({ _id: userToken.userId })
    user.password = password
    await user.save()
    res.status(200).json({
        message: "Password reset was successful, please login"
    })
});

module.exports = {
    registerUser,
    loginUser,
    logoutUser,
    getUser,
    loginStatus,
    updateUser,
    changePassword,
    forgotPassword,
    resetPassword,
}