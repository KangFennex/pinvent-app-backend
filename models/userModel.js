const mongoose = require("mongoose")
const bcrypt = require("bcryptjs");

const userSchema = mongoose.Schema({
    name: {
        type: String,
        required: [true, "Please add a name"]
    },
    email: {
        type: String,
        required: [true, "Please add an email"],
        unique: true,
        trim: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "Please enter a valid email"
        ]
    },
    password: {
        type: String,
        required: [true, "Please select a password"],
        minLength: [6, "Password must contain at least 6 characters"],
        // maxLength: [23, "Password must not contain more than 23 characters"]
    },
    picture: {
        type: String,
        required: [true, "Please add a picture"],
        default: "https://i.ibb.co/4pDNDk1/avatar.png",
    },
    phone: {
        type: String,
        default: "+1"
    },
    bio: {
        type: String,
        default: "I am a person in this universe",
        maxLength: [250, "Bio must not be more than 250 characters"]
    },
},
    {
        timestamps: true,
    }
);

// Encrypt password before saving to DB
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
        return next()
    }

    // Hash password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(this.password, salt);
    this.password = hashedPassword;
    next();
})


const User = mongoose.model("User", userSchema);
module.exports = User;