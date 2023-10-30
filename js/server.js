const express = require("express");
const jwt = require("jsonwebtoken");
const jose = require("node-jose");
const sqlite3 = require("sqlite3");
const crypto = require("crypto");
const forge = require("node-forge");

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;
let db;

function createDB() {
  db = new sqlite3.Database("./totally_not_my_privateKeys.db", (err) => {
    if (err) {
      console.error("Couldn't connect to SQLite database");
      console.error(err);
    } else {
      console.error("Connected to SQLite database");
      db.exec(`CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL);`);
    }
  });
}

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey("RSA", 2048, { alg: "RS256", use: "sig" });

  expiredKeyPair = await jose.JWK.createKey("RSA", 2048, {
    alg: "RS256",
    use: "sig",
  });
}

function generateToken() {
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const payload = {
    user: "sampleUser",
    iat: Math.floor(Date.now() / 1000),
    exp,
  };
  const options = {
    algorithm: "RS256",
    header: {
      typ: "JWT",
      alg: "RS256",
      kid: keyPair.kid,
    },
  };

  token = jwt.sign(payload, keyPair.toPEM(true), options);
  db.run("INSERT INTO keys(key, exp) VALUES(?, ?)", [token, exp], (err) => {
    if (err) {
      return console.log(err.message);
    }
    console.log("Row was added to the keys");
  });
}

function generateExpiredJWT() {
  const exp = Math.floor(Date.now() / 1000) - 3600;
  const payload = {
    user: "sampleUser",
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp,
  };
  const options = {
    algorithm: "RS256",
    header: {
      typ: "JWT",
      alg: "RS256",
      kid: expiredKeyPair.kid,
    },
  };

  // signing expired token
  expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
  // inserting expired token
  db.run(
    "INSERT INTO keys(key, exp) VALUES(?, ?)",
    [expiredToken, exp],
    (err) => {
      if (err) {
        return console.log(err.message);
      }
      console.log("Row was added to the keys");
    }
  );
}

app.all("/auth", (req, res, next) => {
  if (req.method !== "POST") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all("/.well-known/jwks.json", (req, res, next) => {
  if (req.method !== "GET") {
    return res.status(405).send("Method Not Allowed");
  }
  next();
});

app.get("/.well-known/jwks.json", (req, res) => {
  const validKeys = [keyPair].filter((key) => !key.expired);
  res.setHeader("Content-Type", "application/json");
  res.json({ keys: validKeys.map((key) => key.toJSON()) });
});

app.post("/auth", async (req, res) => {
  if (req.query.expired === "true") {
    return await db.get("SELECT * FROM keys WHERE exp <= ?", [
      Math.floor(Date.now() / 1000),
    ]);
  }
  return await db.get("SELECT * FROM keys WHERE exp > ?", [
    Math.floor(Date.now() / 1000),
  ]);
});

generateKeyPairs().then(() => {
  createDB();
  generateToken();
  generateExpiredJWT();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
