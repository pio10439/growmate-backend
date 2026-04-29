const request = require("supertest");
const app = require("../server");

describe("Auth middleware", () => {
  it("should return 401 without token", async () => {
    const res = await request(app).get("/plants");

    expect(res.statusCode).toBe(401);
  });

  it("should pass with token", async () => {
    const res = await request(app)
      .get("/plants")
      .set("Authorization", "Bearer faketoken");

    expect(res.statusCode).not.toBe(401);
  });
});
