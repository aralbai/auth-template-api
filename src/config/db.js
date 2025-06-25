import mongoose from "mongoose";

const connectDB = async () => {
  const MONGO_URL = process.env.MONGO_URL || "";

  try {
    await mongoose.connect(MONGO_URL);

    console.log("MongoDB connected...");
  } catch (err) {
    console.error("Mongodb connection error", err);

    process.exit(1);
  }
};

export default connectDB;
