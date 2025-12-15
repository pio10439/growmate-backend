require("dotenv").config();
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
};
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${process.env.FIREBASE_PROJECT_ID}.firebaseio.com`,
});
const db = admin.firestore();
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("GrowMate Backend is running!");
});

app.post("/plants", upload.single("photo"), async (req, res) => {
  try {
    const { userId, location, type, schedule, lightLevel, temperature, notes } =
      req.body;

    const photoResult = await cloudinary.uploader.upload(req.file.path);
    const plantData = {
      userId,
      photoUrl: photoResult.secure_url,
      location,
      type,
      schedule: JSON.parse(schedule),
      lightLevel,
      temperature,
      notes,
      lastWatered: null,
    };
    const docRef = await db.collection("plants").add(plantData);
    res.status(201).json({ id: docRef.id, ...plantData });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
