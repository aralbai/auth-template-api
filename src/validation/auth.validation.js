import Joi from "joi";

export const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required().messages({
    "string.empty": "Username is required",
    "string.min": "Username must be at least 3 characters",
    "string.max": "Username must be at most 30 characters",
  }),

  password: Joi.string().min(6).required().messages({
    "string.empty": "Password is required",
    "string.min": "Password must be at least 6 characters",
  }),

  role: Joi.string()
    .valid("admin", "student", "parent", "teacher")
    .required()
    .messages({
      "any.only": "Role must be one of admin, student, parent, teacher",
      "string.empty": "Role is required",
    }),
});

export const loginSchema = Joi.object({
  username: Joi.string().required().messages({
    "string.empty": "Username is required",
  }),

  password: Joi.string().required().messages({
    "string.empty": "Password is required",
  }),
});
