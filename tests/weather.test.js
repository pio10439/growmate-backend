const request = require("supertest");
const app = require("../server");

describe("Weather API", () => {
  it("should return 400 for invalid coords", async () => {
    const res = await request(app).get("/weather/abc/xyz");

    expect(res.statusCode).toBe(400);
  });
});
