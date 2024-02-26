import supertest from "supertest";
import { expect } from "chai";
import app from "./../Backend/Server.js";

const request = supertest(app);

describe("JWT/JWKS Server Tests", () => {
	let validKid;

	it("should return JWKS with valid keys", async () => {
		const response = await request.get("/jwks");
		expect(response.status).to.equal(200);
		expect(response.body).to.have.property("keys").that.is.an("array");

		validKid = response.body.keys[0].kid;

		expect(validKid).to.be.a("string");
	});

	it("should issue a JWT with a valid kid obtained from /jwks", async () => {
		const response = await request.post(`/auth?kid=${validKid}`);
		expect(response.status).to.equal(200);
		expect(response.body).to.have.property("token").that.is.a("string");
	});

	it("should handle invalid kid in auth endpoint", async () => {
		const invalidKid = "invalid-kid";
		const response = await request.post(`/auth?kid=${invalidKid}`);
		expect(response.status).to.equal(404);
		expect(response.body).to.have.property("error").that.equals("Key not found");
	});
});
