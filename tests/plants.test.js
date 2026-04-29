const request = require("supertest");
const app = require("../server");

describe("Plants API", () => {
  const token = "faketoken";

  it("should fail when name is missing", async () => {
    const res = await request(app)
      .post("/plants")
      .set("Authorization", `Bearer ${token}`)
      .send({
        type: "Test",
        wateringDays: 7,
        fertilizingDays: 30,
      });

    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  it("should fail with invalid wateringDays", async () => {
    const res = await request(app)
      .post("/plants")
      .set("Authorization", `Bearer ${token}`)
      .send({
        name: "Test",
        type: "Test",
        wateringDays: 999,
        fertilizingDays: 30,
      });

    expect(res.statusCode).toBe(400);
  });

  it("should create plant", async () => {
    const res = await request(app)
      .post("/plants")
      .set("Authorization", `Bearer ${token}`)
      .send({
        name: "Monstera",
        type: "Tropikalna",
        wateringDays: 7,
        fertilizingDays: 30,
      });

    expect(res.statusCode).toBe(201);
    expect(res.body.name).toBe("Monstera");
  });

  it("should get plants", async () => {
    const res = await request(app)
      .get("/plants")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it("should delete plant", async () => {
    const res = await request(app)
      .delete("/plants/123")
      .set("Authorization", `Bearer ${token}`);

    expect(res.statusCode).toBe(200);
  });
});
