require("dotenv").config();
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const axios = require("axios");
const fs = require("fs");
const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

const app = express();
const upload = multer({ dest: "uploads/" });

app.use(cors());
app.use(express.json());

const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Brak tokenu autoryzacji" });
  }
  const token = authHeader.split("Bearer ")[1];
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.userId = decoded.uid;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Nieprawidłowy token" });
  }
};

const createUserRateLimiter = (options) =>
  rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    message: { error: "Zbyt wiele żądań – spróbuj później" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      if (req.userId) {
        return `user:${req.userId}`;
      }

      return ipKeyGenerator(req.ip);
    },
  });

const identifyLimiter = createUserRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
});
const weatherLimiter = createUserRateLimiter({
  windowMs: 10 * 60 * 1000,
  max: 30,
});

const safeJsonParse = (str, fallback) => {
  if (!str) return fallback;
  try {
    return JSON.parse(str);
  } catch (e) {
    return fallback;
  }
};

app.post("/plants", verifyToken, upload.single("photo"), async (req, res) => {
  try {
    const {
      name,
      type,
      location,
      wateringDays,
      fertilizingDays,
      lightLevel,
      temperature,
      notes,
    } = req.body;

    if (!name || name.trim() === "") {
      return res.status(400).json({ error: "Nazwa rośliny jest wymagana" });
    }
    if (!type || type.trim() === "") {
      return res.status(400).json({ error: "Typ rośliny jest wymagany" });
    }

    let photoUrl = null;
    let publicId = null;
    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: "growmate/plants",
      });
      photoUrl = result.secure_url;
      publicId = result.public_id;
      fs.unlinkSync(req.file.path);
    }

    const parsedLocation = safeJsonParse(location, { lat: 0, lng: 0 });

    const wateringInterval = parseInt(wateringDays);
    const fertilizingInterval = parseInt(fertilizingDays);

    if (
      isNaN(wateringInterval) ||
      wateringInterval < 1 ||
      wateringInterval > 365
    ) {
      return res
        .status(400)
        .json({ error: "Nieprawidłowy interwał podlewania (1-365 dni)" });
    }
    if (
      isNaN(fertilizingInterval) ||
      fertilizingInterval < 1 ||
      fertilizingInterval > 365
    ) {
      return res
        .status(400)
        .json({ error: "Nieprawidłowy interwał nawożenia (1-365 dni)" });
    }

    const plantData = {
      userId: req.userId,
      name: name.trim(),
      type: type.trim(),
      location: parsedLocation,
      wateringInterval,
      fertilizingInterval,
      lightLevel: lightLevel?.trim() || "",
      temperature: temperature?.trim() || "",
      notes: notes?.trim() || "",
      photoUrl,
      publicId,
      lastWatered: null,
      lastFertilized: null,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const docRef = await db.collection("plants").add(plantData);
    res.status(201).json({ id: docRef.id, ...plantData });
  } catch (error) {
    console.error("Błąd dodawania rośliny:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.get("/plants", verifyToken, async (req, res) => {
  try {
    const snapshot = await db
      .collection("plants")
      .where("userId", "==", req.userId)
      .orderBy("createdAt", "desc")
      .get();

    const plants = snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));

    res.json(plants);
  } catch (error) {
    console.error("Błąd pobierania roślin:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.put(
  "/plants/:id",
  verifyToken,
  upload.single("photo"),
  async (req, res) => {
    try {
      const plantId = req.params.id;
      const updates = req.body;

      const plantRef = db.collection("plants").doc(plantId);
      const doc = await plantRef.get();

      if (!doc.exists || doc.data().userId !== req.userId) {
        return res.status(404).json({ error: "Roślina nie znaleziona" });
      }

      let updateData = {};

      if (updates.name !== undefined) {
        if (!updates.name || updates.name.trim() === "") {
          return res.status(400).json({ error: "Nazwa nie może być pusta" });
        }
        updateData.name = updates.name.trim();
      }
      if (updates.type !== undefined) {
        if (!updates.type || updates.type.trim() === "") {
          return res.status(400).json({ error: "Typ nie może być pusty" });
        }
        updateData.type = updates.type.trim();
      }
      if (updates.location !== undefined) {
        updateData.location = safeJsonParse(
          updates.location,
          doc.data().location
        );
      }
      if (updates.wateringDays !== undefined) {
        const val = parseInt(updates.wateringDays);
        if (isNaN(val) || val < 1 || val > 365) {
          return res
            .status(400)
            .json({ error: "Nieprawidłowy interwał podlewania" });
        }
        updateData.wateringInterval = val;
      }
      if (updates.fertilizingDays !== undefined) {
        const val = parseInt(updates.fertilizingDays);
        if (isNaN(val) || val < 1 || val > 365) {
          return res
            .status(400)
            .json({ error: "Nieprawidłowy interwał nawożenia" });
        }
        updateData.fertilizingInterval = val;
      }
      if (updates.lightLevel !== undefined)
        updateData.lightLevel = updates.lightLevel.trim();
      if (updates.temperature !== undefined)
        updateData.temperature = updates.temperature.trim();
      if (updates.notes !== undefined) updateData.notes = updates.notes.trim();

      if (req.file) {
        if (doc.data().publicId) {
          await cloudinary.uploader.destroy(doc.data().publicId);
        }
        const result = await cloudinary.uploader.upload(req.file.path, {
          folder: "growmate/plants",
        });
        updateData.photoUrl = result.secure_url;
        updateData.publicId = result.public_id;
        fs.unlinkSync(req.file.path);
      }

      await plantRef.update(updateData);
      res.json({ success: true });
    } catch (error) {
      console.error("Błąd edycji:", error);
      res.status(500).json({ error: "Błąd serwera" });
    }
  }
);

app.delete("/plants/:id", verifyToken, async (req, res) => {
  try {
    const plantRef = db.collection("plants").doc(req.params.id);
    const doc = await plantRef.get();

    if (!doc.exists || doc.data().userId !== req.userId) {
      return res.status(404).json({ error: "Roślina nie znaleziona" });
    }

    if (doc.data().publicId) {
      await cloudinary.uploader.destroy(doc.data().publicId);
    }

    await plantRef.delete();
    res.json({ success: true });
  } catch (error) {
    console.error("Błąd usuwania:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.post("/plants/:id/water", verifyToken, async (req, res) => {
  try {
    const plantRef = db.collection("plants").doc(req.params.id);
    const doc = await plantRef.get();
    if (!doc.exists || doc.data().userId !== req.userId) {
      return res.status(404).json({ error: "Roślina nie znaleziona" });
    }
    await plantRef.update({
      lastWatered: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.post("/plants/:id/fertilize", verifyToken, async (req, res) => {
  try {
    const plantRef = db.collection("plants").doc(req.params.id);
    const doc = await plantRef.get();
    if (!doc.exists || doc.data().userId !== req.userId) {
      return res.status(404).json({ error: "Roślina nie znaleziona" });
    }
    await plantRef.update({
      lastFertilized: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Błąd serwera" });
  }
});

app.get("/weather/:lat/:lng", weatherLimiter, async (req, res) => {
  try {
    const { lat, lng } = req.params;
    if (isNaN(lat) || isNaN(lng)) {
      return res.status(400).json({ error: "Nieprawidłowe współrzędne" });
    }
    const response = await axios.get(
      `https://api.openweathermap.org/data/2.5/forecast?lat=${lat}&lon=${lng}&appid=${process.env.OPENWEATHER_API_KEY}&units=metric&lang=pl`
    );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: "Błąd pobierania pogody" });
  }
});

app.get("/funfact", async (req, res) => {
  try {
    const randomPage = Math.floor(Math.random() * 10) + 1;
    const response = await axios.get(
      `https://perenual.com/api/v2/species-list?key=${process.env.PERENUAL_API_KEY}&page=${randomPage}`
    );

    const plants = response.data.data;
    if (plants.length === 0) {
      return res.json({
        fact: "Nie udało się pobrać ciekawostki. Spróbuj później!",
      });
    }

    const randomPlant = plants[Math.floor(Math.random() * plants.length)];

    const fact = `Ciekawostka o roślinie "${
      randomPlant.common_name
    }": Przyciąga ${randomPlant.attracts?.join(", ") || "różne owady"} i jest ${
      randomPlant.drought_tolerant ? "odporna na suszę" : "wrażliwa na suszę"
    }. Wymaga podlewania: ${
      randomPlant.watering
    }. ${randomPlant.description?.substring(0, 100)}...`;

    res.json({ fact });
  } catch (error) {
    console.error("Błąd pobierania ciekawostki:", error.message);
    res
      .status(500)
      .json({ fact: "Błąd podczas pobierania ciekawostki z API." });
  }
});

app.post(
  "/identify-plant",
  verifyToken,
  identifyLimiter,
  upload.single("photo"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: "Brak zdjęcia" });
      }

      const imageBase64 = fs.readFileSync(req.file.path, {
        encoding: "base64",
      });

      const response = await axios.post(
        "https://api.plant.id/v2/identify",
        {
          images: [`data:${req.file.mimetype};base64,${imageBase64}`],
          plant_details: [
            "common_names",
            "url",
            "wiki_description",
            "taxonomy",
            "synonyms",
            "watering",
            "sunlight",
          ],
          language: "pl",
        },
        {
          headers: {
            "Api-Key": process.env.PLANT_ID_API_KEY,
            "Content-Type": "application/json",
          },
        }
      );

      const suggestions = response.data.suggestions || [];
      if (suggestions.length === 0) {
        fs.unlinkSync(req.file.path);
        return res.json({ error: "Nie udało się rozpoznać rośliny" });
      }

      const best = suggestions[0];
      const plant = best.plant_details;

      const result = {
        name: best.plant_name,
        commonNames: plant.common_names || [],
        probability: Math.round(best.probability * 100),
        description: plant.wiki_description?.value || "Brak opisu",
        watering: plant.watering?.general || "Brak danych",
        sunlight: plant.sunlight || ["Średnie światło"],
        imageUrl: best.images?.[0]?.url || null,
      };

      fs.unlinkSync(req.file.path);
      res.json(result);
    } catch (error) {
      console.error(
        "Błąd identyfikacji rośliny:",
        error.response?.data || error.message
      );
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
      res.status(500).json({ error: "Błąd podczas rozpoznawania rośliny" });
    }
  }
);

app.get("/", (req, res) => {
  res.send("GrowMate Backend ");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Backend działa na porcie ${PORT}`);
});
