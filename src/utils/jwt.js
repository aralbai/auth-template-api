import jwt from "jsonwebtoken";

const ACCES_SECRET = process.env.ACCES_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

export const generateAccessToken = ({ userId, role }) => {
  return jwt.sign(
    {
      userId,
      role,
    },
    ACCES_SECRET,
    {
      expiresIn: "15m",
    }
  );
};

export const generateRefreshToken = ({ userId }) => {
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
