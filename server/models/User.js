/* This is a sample model file for the user schema. 
This file will be used to create a user schema and export it to the server file. */

import mongoose from "mongoose";

const UserSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, "Password is required"],
      unique: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
    },

    name: {
      type: String,
      required: false,
      default: "",
    },

    plan: {
      type: String,
      required: true,
      enum: ["regular", "premium", "standard"],
    },

    isAdmin: {
      type: Boolean,
      default: false,
    },

    refreshToken: {
      type: String,
    },
  },
  {
    timestamps: true, // To store creared or modifiesd time of the record
  }
);

// Encrypting password before saving into the database
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 10);
  next();
});

// Checking Passwords
userSchema.methods.checkPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Get Access Tokens and Refresh Tokens
userSchema.methods.getAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      name: this.name,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    }
  );
};

userSchema.methods.getRefreshToken = function () {
  return jwt.sign(
    {
      _id: this._id,
    },
    process.env.REFRESH_TOKEN_SECRET,
    {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
    }
  );
};

export default mongoose.model("User", UserSchema); // Exporting the model
