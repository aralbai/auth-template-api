import express from "express";
import {
  register,
  login,
  logout,
  getUser,
  refreshToken,
} from "../controllers/auth.controller.js";
import authMiddleware from "../middlewares/auth.middleware.js";
import { authorizeRoles } from "../middlewares/role.middleware.js";

const router = express.Router();

// Public routes
router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refreshToken);
router.post("/logout", logout);

// Protected route – faqat token bor foydalanuvchi
router.get("/me", authMiddleware, getUser);

// Role-based protected route – faqat admin
router.get(
  "/admin-only",
  authMiddleware,
  authorizeRoles("admin"),
  (req, res) => {
    res.json({ message: "Admin content" });
  }
);

//  Role-based protected route – admin yoki teacher
router.get(
  "/manage",
  authMiddleware,
  authorizeRoles("admin", "teacher"),
  (req, res) => {
    res.json({ message: "Admin yoki Teacher kirishi mumkin bo'lgan sahifa" });
  }
);

export default router;
