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

const OpenAI = require("openai");

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

app.get("/plants/:id", verifyToken, async (req, res) => {
  try {
    const plantRef = db.collection("plants").doc(req.params.id);
    const doc = await plantRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "Roślina nie znaleziona" });
    }

    const plantData = doc.data();
    if (plantData.userId !== req.userId) {
      return res.status(403).json({ error: "Brak dostępu" });
    }

    res.json({ id: doc.id, ...plantData });
  } catch (error) {
    console.error("Błąd pobierania rośliny:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

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
    const now = new Date();

    await plantRef.update({
      lastWatered: now,
      wateringHistory: admin.firestore.FieldValue.arrayUnion(now),
    });

    res.json({
      success: true,
      lastWatered: now,
    });
  } catch (error) {
    console.error("Water error:", error);
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
    const now = new Date();

    await plantRef.update({
      lastFertilized: now,
    });
    res.json({
      success: true,
      lastFertilized: now,
    });
  } catch (error) {
    console.error("Fertilize error:", error);
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

const openai = new OpenAI({
  baseURL: "https://openrouter.ai/api/v1",
  apiKey: process.env.OPENROUTER_API_KEY,
});

let cachedPlant = null;
let cacheTimestamp = 0;
const CACHE_TTL = 1000 * 60 * 60 * 6;

const FALLBACK_PLANT = {
  id: 1,
  commonName: "Monstera deliciosa",
  scientificName: "Monstera deliciosa",
  description:
    "Ikona roślin domowych. Jej ogromne, perforowane liście nadają wnętrzom tropikalnego charakteru. Jest odporna, łatwa w pielęgnacji i idealna dla początkujących.",
  watering: "UMIARKOWANE",
  sunlight: "PÓŁCIEŃ",
  origin: "Ameryka Środkowa",
  indoor: "TAK",
  careLevel: "ŁATWY",
  specialFeature: "oczyszczająca",
  why: "idealna na start przygody z roślinami",
  imageUrl:
    "https://upload.wikimedia.org/wikipedia/commons/thumb/2/2e/Monstera_deliciosa2.jpg/1280px-Monstera_deliciosa2.jpg",
};
app.get("/funfact", async (req, res) => {
  try {
    const force = req.query.force === "true";

    if (!force && cachedPlant && Date.now() - cacheTimestamp < CACHE_TTL) {
      return res.json(cachedPlant);
    }

    const randomPage = Math.floor(Math.random() * 10) + 1;
    const listRes = await axios.get("https://perenual.com/api/species-list", {
      params: {
        key: process.env.PERENUAL_API_KEY,
        page: randomPage,
        indoor: 1,
      },
      timeout: 10000,
    });

    const plants = listRes.data?.data;
    if (!plants || plants.length === 0) {
      throw new Error("Brak roślin na stronie");
    }

    const p = plants[Math.floor(Math.random() * plants.length)];

    const prompt = `Jesteś polskim ekspertem od roślin doniczkowych.

Na podstawie nazwy rośliny:
- angielska: "${p.common_name || "nieznana"}"
- łacińska: "${p.scientific_name?.[0] || "nieznana"}"

Zwróć TYLKO czysty JSON (bez komentarzy, bez markdown):

{
  "opis": "2-3 zdania po polsku: przyjazny, ekspercki, angażujący ton",
  "podlewanie": "BARDZO_RZADKIE | RZADKIE | UMIARKOWANE | CZĘSTE",
  "swiatlo": "CIEŃ | PÓŁCIEŃ | ROZPROSZONE | JASNE | PEŁNE_SŁOŃCE",
  "pochodzenie": "region lub kontynent pochodzenia",
  "poziom_opieki": "BARDZO_ŁATWY | ŁATWY | ŚREDNI | TRUDNY",
  "cecha_specjalna": "jedno słowo: np. dekoracyjna, odporna, oczyszczająca",
  "dlaczego": "krótka fraza: dlaczego warto ją mieć w domu"
}`;

    const completion = await openai.chat.completions.create({
      model: "mistralai/devstral-2512:free",
      messages: [
        {
          role: "user",
          content: prompt,
        },
      ],
      temperature: 0.6,
      max_tokens: 220,
      response_format: { type: "json_object" },
    });

    let aiData = {};
    try {
      const rawContent = completion.choices[0].message.content;

      if (!rawContent) {
        throw new Error("Pusta odpowiedź od AI");
      }
      const cleanJson = rawContent
        .replace(/```json/g, "")
        .replace(/```/g, "")
        .trim();

      aiData = JSON.parse(cleanJson);
    } catch (parseError) {
      console.error("Błąd parsowania JSON z AI:", parseError);
    }

    const imageUrl =
      p.default_image?.original_url ||
      p.default_image?.regular_url ||
      p.default_image?.medium_url ||
      p.default_image?.thumbnail ||
      FALLBACK_PLANT.imageUrl;

    const result = {
      id: p.id,
      commonName: p.common_name || "Nieznana roślina",
      scientificName: p.scientific_name?.[0] || "",
      description: aiData.opis || "Piękna roślina doniczkowa.",
      watering: aiData.podlewanie || "UMIARKOWANE",
      sunlight: aiData.swiatlo || "PÓŁCIEŃ",
      origin: aiData.pochodzenie || "Nieznane",
      indoor: "TAK",
      careLevel: aiData.poziom_opieki || "ŁATWY",
      specialFeature: aiData.cecha_specjalna || "dekoracyjna",
      why: aiData.dlaczego || "doda zieleni do wnętrza",
      imageUrl: imageUrl,
    };
    cachedPlant = result;
    cacheTimestamp = Date.now();

    res.json(result);
  } catch (error) {
    console.error("Funfact błąd:", error.message);
    res.json(FALLBACK_PLANT);
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

      const uploadResult = await cloudinary.uploader.upload(req.file.path, {
        folder: "growmate/plants",
        resource_type: "image",
      });

      const photoUrl = uploadResult.secure_url;

      const plantIdResponse = await axios.post(
        "https://plant.id/api/v3/identification",
        {
          images: [imageBase64],
        },
        {
          headers: {
            "Api-Key": process.env.PLANT_ID_API_KEY,
            "Content-Type": "application/json",
          },
        }
      );

      const suggestions =
        plantIdResponse.data?.result?.classification?.suggestions;

      if (!suggestions || suggestions.length === 0) {
        throw new Error("Plant.id nie rozpoznało rośliny");
      }

      const bestMatch = suggestions[0].probability;
      const plantName = suggestions[0].name;

      const prompt = `
Jesteś polskim ekspertem od roślin.

Rozpoznana roślina: "${plantName}"

Zwróć TYLKO czysty JSON (bez markdown, bez komentarzy):

{
  "name": "najlepsza polska nazwa rośliny (lub angielska jeśli nie ma polskiej)",
  "type": "rodzine / rodzaj podanej rosliny (np. Rodzina kaktusowata, Sukulent)",
  "wateringDays": "co ile dni podlewać (np. 7, 10, 14, 21)",
  "fertilizingDays": "co ile dni nawozić (np. 30, 60)",
  "lightLevel": "poziom światła po polsku",
  "temperature": "zakres temperatur (np. 18–24°C) podaj sam zakres bez jednostki temperatury",
  "notes": "krótka praktyczna wskazówka, 1 lub 2 przydatne zdania"
}
`;

      const completion = await openai.chat.completions.create({
        model: "mistralai/devstral-2512:free",
        messages: [
          {
            role: "user",
            content: prompt,
          },
        ],
        temperature: 0.4,
        max_tokens: 220,
        response_format: { type: "json_object" },
      });

      let aiData = {};
      try {
        let raw = completion.choices[0].message.content.trim();
        if (raw.startsWith("```")) raw = raw.replace(/```json|```/g, "");
        aiData = JSON.parse(raw);
      } catch (e) {
        console.error("Błąd parsowania AI:", e.message);
      }
      const cleanTemp = (aiData.temperature || "18-24")
        .toString()
        .replace(/\s+/g, "")
        .replace(/–/g, "-")
        .replace(/[^\d-]/g, "");
      res.json({
        name: aiData.name || plantName,
        type: aiData.type || "Roślina doniczkowa",
        probability: Math.round(bestMatch * 100) || "80",
        wateringDays: aiData.wateringDays || "7",
        fertilizingDays: aiData.fertilizingDays || "30",
        lightLevel: aiData.lightLevel || "Rozproszone światło",
        temperature: cleanTemp || "18–24",
        notes: aiData.notes || "",
        photoUrl,
      });
    } catch (error) {
      if (error.response) {
        console.error("Błąd z serwera Plant.id:", error.response.data);
      } else {
        console.error("Błąd identyfikacji:", error.message);
      }
      res.status(500).json({ error: "Błąd serwera podczas testu" });
    } finally {
      if (req.file && fs.existsSync(req.file.path)) {
        fs.unlinkSync(req.file.path);
      }
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
