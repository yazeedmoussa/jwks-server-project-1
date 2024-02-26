const uuid = require("uuid");
const express = require("express");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const crypto = require("crypto");

const app = express();
const port = 8080;

app.use(morgan("dev"));

const keys = {};

// Function to generate RSA key pair
const generateRSAKeyPair = () => {
	return crypto.generateKeyPairSync("rsa", {
		modulusLength: 2048,
		publicKeyEncoding: { type: "spki", format: "pem" },
		privateKeyEncoding: { type: "pkcs8", format: "pem" },
	});
};

// Generate RSA key pairs with UUIDs as kids
const kid1 = uuid.v4();
const kid2 = uuid.v4();

keys[kid1] = { keyPair: generateRSAKeyPair(), expiresAt: Date.now() + 3600000 }; // Expires in 1 hour
keys[kid2] = { keyPair: generateRSAKeyPair(), expiresAt: Date.now() + 7200000 }; // Expires in 2 hours

// JWKS endpoint to serve public keys
app.get("/jwks", (req, res) => {
	try {
		const now = Date.now();
		const jwks = Object.entries(keys)
			.filter(([kid, keyInfo]) => keyInfo.expiresAt > now) // Only serve keys that have not expired
			.map(([kid, keyInfo]) => ({
				kid,
				kty: "RSA",
				use: "sig",
				alg: "RS256",
				nbf: Math.floor(now / 1000),
				exp: Math.floor(keyInfo.expiresAt / 1000),
				n: keyInfo.keyPair.publicKey.split(" ")[1],
				e: "AQAB",
			}));

		res.json({ keys: jwks });
	} catch (error) {
		console.log(error);
	}
});

// Auth endpoint to issue JWTs
app.post("/auth", (req, res) => {
	const { kid, expired } = req.query;

	// Find the key based on the provided kid
	const selectedKey = keys[kid];

	if (!selectedKey) {
		return res.status(404).json({ error: "Key not found" });
	}

	// Use the selected key pair for signing
	const keyPair = expired === "true" ? selectedKey.keyPair : generateRSAKeyPair();

	// Create a JWT using the selected key
	const token = jwt.sign({ data: "payload" }, keyPair.privateKey, { algorithm: "RS256", keyid: kid });

	res.json({ token });
});

app.listen(port, () => {
	console.log(`Server is running on http://localhost:${port}`);
});

module.exports = app;
