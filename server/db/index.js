import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";

const connectDB = async () => {
  try {
    // Connecting to the database
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URL}/${DB_NAME}`
    );
    console.log(
      `\nMongoDB connected!!! DB_host : ${connectionInstance.connection.host}`
    );
  } catch (error) {
    console.log("Error : ", error);
    process.exit(1);
  }
};

export default connectDB;
