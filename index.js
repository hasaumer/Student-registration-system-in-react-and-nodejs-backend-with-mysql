const express = require('express');
const cors = require('cors');
const db = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = 5000;
const JWT_SECRET = 'my_super_secret_key_123';

// Multer Setup for Image Uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Save in 'uploads' folder
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // e.g., 12345678.jpg
    }
});
const upload = multer({ storage: storage });

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (images) from the 'uploads' folder
app.use('/uploads', express.static('uploads'));

// --- AUTH ROUTES ---

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const sql = "SELECT * FROM admins WHERE username = ?";
    
    db.query(sql, [username], async (err, data) => {
        if (err) return res.status(500).json(err);
        if (data.length === 0) return res.status(401).json({ error: "User not found" });

        const user = data[0];

        // First time setup: set password to 'admin123' if empty
        if (user.password === '') {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            db.query("UPDATE admins SET password = ? WHERE id = ?", [hashedPassword, user.id]);
            user.password = hashedPassword;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, username: user.username });
    });
});

// Change Password
app.post('/change-password', verifyToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const username = req.user.username;

    db.query("SELECT * FROM admins WHERE username = ?", [username], async (err, data) => {
        if (err || data.length === 0) return res.status(500).json({ error: "User error" });
        
        const user = data[0];
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        
        if (!isMatch) return res.status(400).json({ error: "Old password is incorrect" });

        const hashedNew = await bcrypt.hash(newPassword, 10);
        db.query("UPDATE admins SET password = ? WHERE username = ?", [hashedNew, username], (err2) => {
            if (err2) return res.status(500).json(err2);
            res.json({ message: "Password changed successfully" });
        });
    });
});

// Middleware to verify token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "No token provided" });

    try {
        const decoded = jwt.verify(token.split(" ")[1], JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: "Unauthorized" });
    }
}

// --- STUDENT ROUTES ---

// Create Student (with Image)
app.post('/students', verifyToken, upload.single('image'), (req, res) => {
    const { name, email, phone, address, course } = req.body;
    const imageName = req.file ? req.file.filename : 'default.jpg';
    const sql = "INSERT INTO students (name, email, phone, address, course, profile_image) VALUES (?, ?, ?, ?, ?, ?)";
    
    db.query(sql, [name, email, phone, address, course, imageName], (err, result) => {
        if (err) return res.status(500).json(err);
        res.status(201).json({ message: "Student added successfully" });
    });
});

// Get All Students
app.get('/students', verifyToken, (req, res) => {
    db.query("SELECT * FROM students", (err, data) => {
        if (err) return res.status(500).json(err);
        res.json(data);
    });
});

// Get Single Student (For Print View)
app.get('/students/:id', verifyToken, (req, res) => {
    db.query("SELECT * FROM students WHERE id = ?", [req.params.id], (err, data) => {
        if (err) return res.status(500).json(err);
        res.json(data[0]);
    });
});

// Update Student
app.put('/students/:id', verifyToken, upload.single('image'), (req, res) => {
    const { id } = req.params;
    const { name, email, phone, address, course } = req.body;
    
    let sql, params;
    
    // If new image uploaded, update it. Otherwise keep old one.
    if (req.file) {
        sql = "UPDATE students SET name=?, email=?, phone=?, address=?, course=?, profile_image=? WHERE id=?";
        params = [name, email, phone, address, course, req.file.filename, id];
    } else {
        sql = "UPDATE students SET name=?, email=?, phone=?, address=?, course=? WHERE id=?";
        params = [name, email, phone, address, course, id];
    }

    db.query(sql, params, (err, result) => {
        if (err) return res.status(500).json(err);
        res.json({ message: "Student updated successfully" });
    });
});

// Delete Student
app.delete('/students/:id', verifyToken, (req, res) => {
    db.query("DELETE FROM students WHERE id = ?", [req.params.id], (err, result) => {
        if (err) return res.status(500).json(err);
        res.json({ message: "Student deleted successfully" });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});