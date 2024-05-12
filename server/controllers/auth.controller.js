import User from "../models/User.js";
import { CreateSuccess } from "../utils/success.js";
import { CreateError } from "../utils/error.js";

// generating access and refresh tokens using schema methods
const generateTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.getAccessToken();
    const refreshToken = user.getRefreshToken();

    // console.log(accessToken);
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new CreateError(500, "Something went wrong while generating tokens");
  }
};

// Register User
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, plan } = req.body;

  if ([name, email, password].some((f) => f?.trim() === "")) {
    throw new CreateError(400, "All fields are compulsary");
  }

  const alreadyRegister = await User.findOne({
    $or: [{ name }, { email }],
  });

  // User already present in the database
  if (alreadyRegister) {
    throw new CreateError(409, "User with email or username already exists");
  }

  const user = await User.create({
    email,
    password,
    name: username.toLowerCase(),
    plan: plan.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  // Final Check
  if (!createdUser) {
    throw new CreateError(500, "User not registered.");
  }

  return res
    .status(201)
    .json(new CreateSuccess(200, "User Registered Successfully.", createdUser));
});

// Login User
const logIn = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  if (!name && !email) {
    throw new CreateError(400, "All fields are compulsary.");
  }

  const user = await User.findOne({
    $or: [{ name }, { email }],
  });

  if (!user) {
    throw new CreateError(404, "User does not exist");
  }
  // Password Validation
  const isPasswordValid = await user.checkPassword(password);

  if (!isPasswordValid) {
    throw new CreateError(401, "Invalid user credentials");
  }

  const { accessToken, refreshToken } = await generateTokens(user._id);

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new CreateSuccess(200, "User logged in Successfully.", {
        accessToken,
        refreshToken,
        user: loggedInUser,
      })
    );
});

// Logout User
const logout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $unset: {
        refreshToken: 1,
      },
    },
    {
      new: true,
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new CreateSuccess(200, "User logged Out"), {});
});

// Update User Password
const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user.id);
  // Checking the existing password matches with the database
  const isPasswordCorrect = await user.checkPassword(oldPassword);

  if (!isPasswordCorrect) {
    throw new CreateError(400, "Invalid old password.");
  }

  user.password = newPassword;
  user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new CreateSuccess(200, "Password changed successfully", {}));
});

// Returns logged in current user info
const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new CreateSuccess(200, "User fetched successfully", req.user));
});

// Updating Tokens
const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken;

  if (!incomingRefreshToken) throw new CreateError(401, "Unauthorized Request");

  const decodedToken = jwt.verify(
    incomingRefreshToken,
    process.env.REFRESH_TOKEN_SECRET
  );

  const user = await User.findById(decodedToken?._id);
  if (!user) throw new CreateError(401, "Invalid refresh token");

  if (incomingRefreshToken !== user?.refreshToken) {
    throw new CreateError(401, "Refresh Token is expired or used.");
  }

  const options = {
    httpOnly: true,
    secure: true,
  };

  const { accessToken, newRefreshToken } = await generateTokens(user._id);

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new CreateSuccess(200, "Tokens Refreshed.", {
        accessToken,
        newRefreshToken,
      })
    );
});

// Updating User Emails
const updateAccountEmail = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new CreateError(400, "Email is required");
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        email,
      },
    },
    { new: true }
  ).select("-password");

  return res
    .send(200)
    .json(new CreateSuccess(200, "User details successfully updated."), user);
});
