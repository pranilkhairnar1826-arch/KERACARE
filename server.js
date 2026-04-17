const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Support dynamic data directory for Render persistent disks
const DATA_DIR = process.env.DATA_DIR || __dirname;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(DATA_DIR, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(DATA_DIR, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Initialize Database
const dbPath = path.join(DATA_DIR, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error connecting to SQLite:', err.message);
    else console.log('Connected to SQLite database.');
});

// Create Users Table
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mobile TEXT UNIQUE NOT NULL,
        firstName TEXT,
        lastName TEXT,
        passwordHash TEXT NOT NULL,
        dob TEXT,
        gender TEXT,
        bloodGroup TEXT,
        address TEXT,
        phone TEXT,
        email TEXT,
        height INTEGER,
        weight INTEGER,
        doctor TEXT,
        conditions TEXT,
        allergies TEXT,
        emergencyName TEXT,
        emergencyRelation TEXT,
        emergencyPhone TEXT,
        emergencyEmail TEXT
    )`);

    // Create Doctors Table
    db.run(`CREATE TABLE IF NOT EXISTS doctors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        mobile TEXT UNIQUE,
        mrn TEXT,
        specialization TEXT,
        experience INTEGER,
        clinic TEXT,
        city TEXT,
        passwordHash TEXT,
        degreePath TEXT,
        licensePath TEXT,
        idproofPath TEXT
    )`);
});

// --- API ENDPOINTS ---

// 1. REGISTER
app.post('/api/register', async (req, res) => {
    const { firstName, lastName, mobile, dob, gender, password } = req.body;

    if (!mobile || !password || !firstName) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);

        const stmt = db.prepare(`INSERT INTO users (firstName, lastName, mobile, dob, gender, passwordHash) VALUES (?, ?, ?, ?, ?, ?)`);
        stmt.run([firstName, lastName, mobile, dob, gender, passwordHash], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ error: 'An account with this mobile number already exists.' });
                }
                return res.status(500).json({ error: 'Database error.' });
            }
            res.status(201).json({ message: 'User registered successfully!' });
        });
        stmt.finalize();
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

// DOCTOR REGISTRATION
const doctorUploads = upload.fields([
    { name: 'degree', maxCount: 1 },
    { name: 'license', maxCount: 1 },
    { name: 'idproof', maxCount: 1 }
]);

app.post('/api/doctor/register', doctorUploads, async (req, res) => {
    const { name, email, mobile, mrn, specialization, experience, clinic, city, password } = req.body;
    
    if (!name || !email || !mobile || !password) {
        return res.status(400).json({ error: 'Missing required fields.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        
        let degreePath = req.files && req.files['degree'] ? req.files['degree'][0].path : null;
        let licensePath = req.files && req.files['license'] ? req.files['license'][0].path : null;
        let idproofPath = req.files && req.files['idproof'] ? req.files['idproof'][0].path : null;

        const stmt = db.prepare(`INSERT INTO doctors 
            (name, email, mobile, mrn, specialization, experience, clinic, city, passwordHash, degreePath, licensePath, idproofPath) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
            
        stmt.run([name, email, mobile, mrn, specialization, parseInt(experience)||0, clinic, city, passwordHash, degreePath, licensePath, idproofPath], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(409).json({ error: 'An account with this email/mobile already exists.' });
                }
                return res.status(500).json({ error: 'Database error.' });
            }
            res.status(201).json({ message: 'Doctor registered successfully!' });
        });
        stmt.finalize();
    } catch (err) {
        res.status(500).json({ error: 'Server error.' });
    }
});

// 2. LOGIN
app.post('/api/login', (req, res) => {
    const { mobile, password } = req.body;

    if (!mobile || !password) return res.status(400).json({ error: 'Missing credentials.' });

    db.get(`SELECT * FROM users WHERE mobile = ?`, [mobile], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (!user) return res.status(401).json({ error: 'Invalid mobile number or password.' });

        // Compare password
        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) return res.status(401).json({ error: 'Invalid mobile number or password.' });

        // Don't send hash back
        delete user.passwordHash;
        res.status(200).json({ message: 'Login successful.', user });
    });
});

// 3. GET USER INFO
app.get('/api/user/:mobile', (req, res) => {
    const { mobile } = req.params;
    db.get(`SELECT * FROM users WHERE mobile = ?`, [mobile], (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (!user) return res.status(404).json({ error: 'User not found.' });

        delete user.passwordHash;
        res.status(200).json(user);
    });
});

// GET ALL USERS (Helper for backend viewing)
app.get('/api/users', (req, res) => {
    db.all(`SELECT * FROM users`, [], (err, users) => {
        if (err) return res.status(500).json({ error: 'Database error.' });

        users.forEach(u => delete u.passwordHash);
        res.status(200).json(users);
    });
});

// GET ALL DOCTORS (For tabular viewing)
app.get('/api/doctors', (req, res) => {
    db.all(`SELECT * FROM doctors`, [], (err, doctors) => {
        if (err) return res.status(500).json({ error: 'Database error.' });

        doctors.forEach(d => delete d.passwordHash);
        res.status(200).json(doctors);
    });
});

// 4. UPDATE USER PROFILE
app.put('/api/user/:mobile', (req, res) => {
    const { mobile } = req.params;
    const {
        firstName, lastName, dob, gender, bloodGroup, address, phone, email,
        height, weight, doctor, conditions, allergies,
        emergencyName, emergencyRelation, emergencyPhone, emergencyEmail
    } = req.body;

    const sql = `UPDATE users SET 
        firstName = ?, lastName = ?, dob = ?, gender = ?, bloodGroup = ?, 
        address = ?, phone = ?, email = ?, height = ?, weight = ?, doctor = ?, 
        conditions = ?, allergies = ?, emergencyName = ?, emergencyRelation = ?, 
        emergencyPhone = ?, emergencyEmail = ?
        WHERE mobile = ?`;

    const params = [
        firstName, lastName, dob, gender, bloodGroup, address, phone, email,
        height, weight, doctor, conditions, allergies,
        emergencyName, emergencyRelation, emergencyPhone, emergencyEmail,
        mobile
    ];

    db.run(sql, params, function (err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found.' });

        res.status(200).json({ message: 'Profile updated successfully.' });
    });
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
