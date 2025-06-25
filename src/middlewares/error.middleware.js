export const errorHandler = (err, req, res, next) => {
  console.error("Server error:", err);

  const statusCode = err.statusCode || 500;

  const message = err.message || "Internal server error";

  return res.status(statusCode).json({ message });
};
