const dotenv = require("dotenv").config()
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoutes = require("./routes/userRoutes");
const contactRoute = require("./routes/contactRoute");
const productRoute = require("./routes/productRoute");
const errorHandler = require("./middlewares/errorMiddleware");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();

// Middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors({
    origin: ["http://localhost:3000", "https://pinvent-app-kangkm.vercel.app"],
    credentials: true
}));

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Routes Middleware
app.use("/api/users", userRoutes);
app.use("/api/products", productRoute);
app.use("/api/contact", contactRoute);

// Routes
app.get("/", (req, res) => {
    res.send("Homepage")
});

// Error Middleware
app.use(errorHandler);

// Connect to MongoDB + start server
const PORT = process.env.PORT || 5000;
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`)
        })
    })
    .catch((err) => console.log(err))