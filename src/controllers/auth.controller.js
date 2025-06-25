import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "../validation/auth.validation.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import jwt, { decode } from "jsonwebtoken";

const NODE_ENV = process.env.NODE_ENV;

export const register = async (req, res, next) => {
  const { error } = registerSchema.validate(req.body);

  if (error) {
    const messages = error.details.map((detail) => detail.message);

    return res.status(400).json({
      message: messages,
    });
  }

  try {
    const { username, password, role } = req.body;

    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(409).json({
        message: "User already exists",
      });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
      role,
    });

    const savedUser = await newUser.save();

    const token = generateToken(savedUser);

    res.cookie("token", token, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      message: "User registered successfully",
      user: {
        username: savedUser.username,
        role: savedUser.role,
      },
    });
  } catch (err) {
    next(err);
  }
};

export const login = async (req, res, next) => {
  const { error } = loginSchema.validate(req.body);
  if (error) {
    const messages = error.details.map((detail) => detail.message);

    return res.status(400).json({
      message: messages,
    });
  }

  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    const accessToken = generateAccessToken({
      userId: user._id,
      role: user.role,
    });
    const refreshToken = generateRefreshToken({
      userId: user._id,
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: "Logged in successfully",
      accessToken,
      user: {
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    next(err);
  }
};

export const logout = (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "Strict",
  });

  return res.status(200).json({
    message: "Logged out successfully",
  });
};

export const getUser = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    return res.status(200).json(user);
  } catch (err) {
    next(err);
  }
};

export const refreshToken = (req, res, next) => {
  const token = req.cookies?.refreshToken;
  if (!token) {
    return res.status(401).json({
      message: "Refresh token missing",
    });
  }

  try {
    const REFRESH_SECRET = process.env.REFRESH_SECRET;
    const decoded = jwt.verify(token, REFRESH_SECRET);

    const accessToken = generateAccessToken({
      userId: decoded.userId,
      role: decoded.role,
    });

    return res.json({ accessToken });
  } catch (err) {
    return res.status(403).json({
      message: "Invalid refresh token",
    });
  }
};
