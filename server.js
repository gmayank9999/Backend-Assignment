const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Load environment variables from .env
dotenv.config();

// Import the User model
const User = require("./models/user");

// Initialize Express app
const app = express();
app.use(express.json()); // To parse JSON data in request bodies

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("Error connecting to MongoDB:", err));

// Validation Schema using Joi
const userValidationSchema = Joi.object({
  name: Joi.string().required(),
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  role: Joi.string().valid("admin", "user").optional(),
});

// Role-based middleware
const checkRole = (role) => {
  return (req, res, next) => {
    const userRole = req.body.role; // Assume role comes from request body
    if (userRole !== role) {
      return res.status(403).send("Access denied.");
    }
    next();
  };
};

// Root route to handle GET requests to /
app.get("/", (req, res) => {
    res.send("Welcome to the backend server!");
  });
  

// POST /create - Create new user
app.post("/create", checkRole("admin"), async (req, res) => {
  const { error } = userValidationSchema.validate(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  const { name, email, password, role } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).send("User already exists.");
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10); // 10 rounds of salting

  const user = new User({ name, email, password: hashedPassword, role });
  try {
    await user.save();
    res.status(201).send(user);
  } catch (err) {
    res.status(400).send("Error saving user.");
  }
});

// GET /all - Get all users
app.get("/all", async (req, res) => {
  try {
    const users = await User.find();
    res.status(200).send(users);
  } catch (err) {
    res.status(500).send("Error retrieving users.");
  }
});

// GET /byId/:id - Get user by ID
app.get("/byId/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send("User not found.");
    }
    res.status(200).send(user);
  } catch (err) {
    res.status(500).send("Error retrieving user.");
  }
});

// PUT /update/:id - Update user by ID
app.put("/update/:id", checkRole("admin"), async (req, res) => {
  const { error } = userValidationSchema.validate(req.body);
  if (error) {
    return res.status(400).send(error.details[0].message);
  }

  // Hash the password if it's updated
  if (req.body.password) {
    req.body.password = await bcrypt.hash(req.body.password, 10);
  }

  try {
    const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedUser) {
      return res.status(404).send("User not found.");
    }
    res.status(200).send(updatedUser);
  } catch (err) {
    res.status(500).send("Error updating user.");
  }
});

// DELETE /delete/:id - Delete user by ID
app.delete("/delete/:id", checkRole("admin"), async (req, res) => {
  try {
    const deletedUser = await User.findByIdAndDelete(req.params.id);
    if (!deletedUser) {
      return res.status(404).send("User not found.");
    }
    res.status(200).send("User deleted.");
  } catch (err) {
    res.status(500).send("Error deleting user.");
  }
});

// POST /login - User login and JWT token generation
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send("User not found.");
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send("Invalid password.");
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).send({ token });
  } catch (err) {
    res.status(500).send("Error logging in.");
  }
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
