// this code defines a middleware function (verifyToken)
// that checks for the presence of a JWT in the "Authorization" header of an
// incoming request, verifies its authenticity, and attaches the decoded user
// information to the request object for further processing. If the token is missing
// or invalid, it responds with an "Access Denied" message or a 500 internal server error.

import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
  try {
    let token = req.header("Authorization");

    if (!token) {
      return res.status(403).send("Access Denied");
    }

    if (token.startsWith("Bearer ")) {
      token = token.slice(7, token.length).trimLeft();
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
