import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "../validation/auth.validation.js";
import { generateAccessToken, generateRefreshToken } from "../utils/jwt.js";
import jwt from "jsonwebtoken";

const NODE_ENV = process.env.NODE_ENV;

//REGISTER NEW USER
export const register = async (req, res, next) => {
  // 1. Validate req.body
  const { error } = registerSchema.validate(req.body);
  if (error) {
    const messages = error.details.map((detail) => detail.message);

    return res.status(400).json({
      message: messages,
    });
  }

  try {
    const { username, password, role } = req.body;

    // 2. Check existing user
    const existingUser = await User.findOne({ username });
    if (existingUser)
      return res.status(409).json({
        message: "User already exists",
      });

    // 3. Password hashing
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. Create new user object
    const newUser = new User({
      username,
      password: hashedPassword,
      role,
    });

    // 5. Save the user
    const savedUser = await newUser.save();

    // 4. Generate access token
    const accessToken = generateAccessToken({
      userId: savedUser._id,
      role: savedUser.role,
    });

    // 5. Generate refresh token
    const refreshToken = generateRefreshToken({
      userId: savedUser._id,
    });

    // 6. Set the refresh token to httpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // 7. Sending response. User and access token
    return res.status(200).json({
      message: "User registered successfully",
      accessToken,
      user: {
        username: savedUser.username,
        role: savedUser.role,
      },
    });
  } catch (err) {
    next(err);
  }
};

// LOGIN USER
export const login = async (req, res, next) => {
  // 1. Validate req.body with Joi validation
  const { error } = loginSchema.validate(req.body);
  if (error) {
    const messages = error.details.map((detail) => detail.message);

    return res.status(400).json({
      message: messages,
    });
  }

  try {
    const { username, password } = req.body;

    // 2. Check exists user by username
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    // 3. Check password is correct
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(400).json({
        message: "Invalid credentials",
      });
    }

    // 4. Generate access token
    const accessToken = generateAccessToken({
      userId: user._id,
      role: user.role,
    });

    // 5. Generate refresh token
    const refreshToken = generateRefreshToken({
      userId: user._id,
    });

    // 6. Set the refresh token to httpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: NODE_ENV === "production",
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    // 7. Sending response. User and access token
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

// LOGOUT USER
export const logout = (req, res) => {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: NODE_ENV === "production",
    sameSite: "Strict",
  });

  return res.status(200).json({
    message: "Logged out successfully",
  });
};

// GET USER
export const getUser = async (req, res, next) => {
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

// REFRESH TOKEN
export const refreshToken = async (req, res) => {
  // 1. Check refresh token
  const token = req.cookies?.refreshToken;
  if (!token) {
    return res.status(401).json({
      message: "Refresh token missing",
    });
  }

  try {
    // 2. Verify refresh token
    const REFRESH_SECRET = process.env.REFRESH_SECRET;
    const decoded = jwt.verify(token, REFRESH_SECRET);

    // 3. Find user with refresh token decoded userId
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(400).json({
        message: "Invalid refresh token",
      });
    }

    // 4. Generate access token
    const accessToken = generateAccessToken({
      userId: user._id,
      role: user.role,
    });

    // 5. Send response. Access token
    return res.json({ accessToken });
  } catch (err) {
    return res.status(403).json({
      message: "Invalid refresh token",
    });
  }
};
