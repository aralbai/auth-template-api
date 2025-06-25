import jwt from "jsonwebtoken";

export const generateAccessToken = ({ userId, role }) => {
  const ACCESS_SECRET = process.env.ACCESS_SECRET;
  if (!process.env.ACCESS_SECRET) throw new Error("ACCESS_SECRET is missing");

  return jwt.sign(
    {
      userId,
      role,
    },
    ACCESS_SECRET,
    {
      expiresIn: "15m",
    }
  );
};

export const generateRefreshToken = ({ userId }) => {
  const REFRESH_SECRET = process.env.REFRESH_SECRET;
  if (!REFRESH_SECRET) {
    if (!process.env.REFRESH_SECRET)
      throw new Error("REFRESH_SECRET is missing");
  }

  return jwt.sign(
    {
      userId,
    },
    REFRESH_SECRET,
    {
      expiresIn: "7d",
    }
  );
};
