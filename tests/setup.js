jest.mock("@openrouter/sdk", () => ({
  OpenRouter: jest.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: jest.fn(),
      },
    },
  })),
}));

jest.mock("firebase-admin", () => {
  const firestoreMock = {
    collection: jest.fn(() => ({
      add: jest.fn().mockResolvedValue({ id: "123" }),
      where: jest.fn().mockReturnThis(),
      orderBy: jest.fn().mockReturnThis(),
      get: jest.fn().mockResolvedValue({ docs: [] }),
      doc: jest.fn(() => ({
        get: jest.fn().mockResolvedValue({
          exists: true,
          data: () => ({ userId: "testUser" }),
        }),
        update: jest.fn(),
        delete: jest.fn(),
      })),
    })),
  };

  return {
    initializeApp: jest.fn(),
    credential: { cert: jest.fn() },
    auth: () => ({
      verifyIdToken: jest.fn().mockResolvedValue({ uid: "testUser" }),
      getUser: jest.fn().mockResolvedValue({
        metadata: { creationTime: new Date().toISOString() },
      }),
    }),
    firestore: Object.assign(() => firestoreMock, {
      FieldValue: {
        serverTimestamp: jest.fn(() => new Date()),
        arrayUnion: jest.fn(),
      },
    }),
  };
});
const request = require("supertest");
const app = require("../server");
