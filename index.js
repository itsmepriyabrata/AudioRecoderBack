require("dotenv").config(); // Load environment variables
const express = require("express");
const app = express();
const cors = require("cors");
const mongoose = require("mongoose");
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require("./db/conn.js");
const jwt = require('jsonwebtoken');
const PORT = 6005;
const session = require("express-session");
const passport = require("passport");
const OAuth2Strat = require("passport-google-oauth2").Strategy;
const { userdb } = require("./model/userschema");
const { Recording } = require("./model/recordshema");

// Use environment variables for sensitive information
const clientid = process.env.GOOGLE_CLIENT_ID || "";
const clientsecret = process.env.GOOGLE_CLIENT_SECRET || "";

const allowedOrigins = [
  "https://recorder-front.onrender.com",
  "https://recorder-front.onrender.com/login",
  "https://recorder-front.onrender.com/dashboard",
  "https://recorder-front.onrender.com/rewards"
];

app.use(cors({
  origin: allowedOrigins,
  methods: "GET,POST,PUT,DELETE",
  credentials: true
}));

app.get('/audio/[]', (req, res) => {
  const filePath = req.params.filePath;
  const fullPath = path.join(__dirname, filePath);
  if (fs.existsSync(fullPath)) {
    const fileStream = fs.createReadStream(fullPath);
    res.setHeader('Content-Type', 'audio/mpeg'); // Set audio content type
    fileStream.pipe(res);
  } else {
    res.status(404).send('File not found');
  }
});

app.use(express.json());

// Setting up session 
app.use(session({
  secret: process.env.SESSION_SECRET || "default_secret", // Use environment variable for session secret
  resave: false,
  saveUninitialized: true
}));

app.use('/uploads', express.static('uploads'));
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new OAuth2Strat({
    clientID: clientid,
    clientSecret: clientsecret,
    callbackURL: "/auth/google/callback",
    scope: ["profile", "email"]
  },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await userdb.findOne({ googleID: profile.id });
        if (!user) {
          user = new userdb({
            googleID: profile.id,
            displayName: profile.displayName,
            email: profile.emails[0].value,
            password: "",
            image: profile.photos[0].value
          });
          await user.save();
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", {
  successRedirect: "https://recorder-front.onrender.com/",
  failureRedirect: "https://recorder-front.onrender.com/login"
}));

app.get('/login/success', async (req, res) => {
  if (req.user) {
    res.status(200).json({ message: "User logged in", user: req.user });
  } else {
    res.status(400).json({ message: "Not authenticated" });
  }
});

app.post('/updateUser', async (req, res) => {
  const { googleID, displayName, email, password } = req.body;
  try {
    const updatedUser = await userdb.findOneAndUpdate(
      { googleID: googleID },
      { displayName: displayName, email: email, password: password },
      { new: true }
    );
    res.status(200).json({ message: 'User updated successfully', user: updatedUser });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user', error });
  }
});

function generateUniqueId() {
  const timestamp = Date.now(); // Current timestamp in milliseconds
  const randomPart = Math.floor(Math.random() * 10000); // Random number to add variability
  return `${timestamp}-${randomPart}`;
}

app.post('/signup', async (req, res) => {
  const { displayName, email, password } = req.body;
  try {
    const newUser = new userdb({
      googleID: generateUniqueId(),
      displayName: displayName,
      email: email,
      password: password,
      image: ""
    });
    await newUser.save();
    res.status(201).json({ message: 'User created successfully', created: true });
  } catch (error) {
    res.status(500).json({ message: 'Error signing up', error });
  }
});

app.post('/login', async (req, res) => {
  res.header("Access-Control-Allow-Origin", allowedOrigins);
  res.header("Access-Control-Allow-Credentials", "true");
  const { email, password } = req.body;

  try {
    const user = await userdb.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email' });
    }
    const isMatch = password === user.password;
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid Password' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'default_secret_key'); // Use an environment variable for the secret key
    res.status(200).json({ message: 'Login successful', token, user: user });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error });
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("https://localhost:3000");
  });
});

// Base upload path
const baseUploadPath = path.join('..', 'client', 'public', 'uploads');

// Set up multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let subFolder = '';
    if (file.mimetype.startsWith('audio')) {
      subFolder = 'audio';
    } else if (file.mimetype.startsWith('video')) {
      subFolder = 'video';
    }
    const uploadPath = path.join(baseUploadPath, subFolder);
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true }); // Create directory if it does not exist
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const upload = multer({ storage });

app.post('/saveRecording', upload.single('file'), async (req, res) => {
  let { language, transcript, user, Duration } = req.body;
  let filePath = req.file.path;
  filePath = filePath.split(path.sep).join('/');

  const prefix = path.join('..', 'client', 'public');
  const normalizedPrefix = prefix.split(path.sep).join('/');
  filePath = filePath.replace(normalizedPrefix + '/', '');

  const fileExtension = path.extname(req.file.originalname).toLowerCase();
  let mediaType = '';
  if (fileExtension === '.mp3') {
    mediaType = 'audio';
  } else if (fileExtension === '.mp4') {
    mediaType = 'video';
  }
  
  const download = 0;
  let newRecording = new Recording(
    { 
      language: language, 
      transcript: transcript,
      mediatype: mediaType,
      User_ID: user, 
      filePath: filePath,
      Duration: Duration,
      Downloads: download
    }
  );
  await newRecording.save();
  res.json({ message: 'Recording saved successfully', filePath });
});

app.post('/update-downloads', async (req, res) => {
  const { itemIds } = req.body; // Expecting an array of item IDs
  if (!Array.isArray(itemIds) || itemIds.length === 0) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  try {
    const updatePromises = itemIds.map(id => 
      Recording.findByIdAndUpdate(id, { $inc: { Downloads: 1 } }, { new: true })
    );

    const updatedItems = await Promise.all(updatePromises);
    res.json({ success: true, updatedItems });
  } catch (error) {
    console.error('Error updating download counts:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/data', async (req, res) => {
  try {
    const data = await Recording.find();
    res.json(data);
  } catch (err) {
    res.status(500).send(err);
  }
});

app.listen(PORT, () => {
  console.log(`Server Started at ${PORT}`);
});

