import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer")) {
    return res.status(401).json({
      message: "No token provided",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const ACCESS_SECRET = process.env.ACCESS_SECRET;

    const decoded = jwt.verify(token, ACCESS_SECRET);

    req.userId = decoded.userId;
    req.role = decoded.role;

    next();
  } catch (err) {
    return res.status(401).json({
      message: "Unauthorized: Invalid or expired token",
    });
  }
};

export default authMiddleware;
