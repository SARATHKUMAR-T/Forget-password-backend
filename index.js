import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bcrypt, { compare } from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import { User } from "./userDetails.js";
import dbConnnection from "./db.js";
import nodemailer from "nodemailer";

const app = express();

// middlewares
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: false }));

// connecting to DB
dbConnnection();

app.listen(process.env.PORT, () => {
  console.log("Server Started");
});

// Signup User
app.post("/signup", async (req, res) => {
  try {
    const signupUser = await User.findOne({ email: req.body.email });

    if (signupUser) {
      return res
        .status(400)
        .json({ message: "user already exists", existingUser: true });
    }

    const hashedPassword = bcrypt.hashSync(req.body.password, 10);

    const newUser = await new User({
      ...req.body,
      password: hashedPassword,
    }).save();

    const token = jwt.sign({ id: newUser._id }, process.env.SECRET_KEY);

    newUser
      ? res
          .status(200)
          .json({ message: "user created successfully", newUser, token })
      : res.status(500).json({ message: "unable to create new user" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "internal server error", error });
  }
});

// login user
app.post("/login", async (req, res) => {
  try {
    const loginUser = await User.findOne({ email: req.body.email });

    if (!loginUser) {
      return res.status(500).json({ message: "user doesn't exist" });
    }

    const validatePassword = await bcrypt.compare(
      req.body.password,
      loginUser.password
    );

    if (!validatePassword) {
      return res.status(400).json({ message: "invalid credentials" });
    }

    const token = jwt.sign({ id: loginUser._id }, process.env.SECRET_KEY);

    res
      .status(200)
      .json({ message: "user logged in successfully", user: true, token });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "internal server error", error });
  }
});

// forgot-password
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    const oldUser = await User.findOne({ email });
    if (!oldUser) {
      return res.json({ message: "User Not Exists!!", user: false });
    }
    const secret = process.env.SECRET_KEY + oldUser.password;
    const token = jwt.sign({ email: oldUser.email, id: oldUser._id }, secret, {
      expiresIn: "15m",
    });
    const link = `https://forgot-password-1.netlify.app/reset-password/${oldUser._id}/${token}`;

    var transporter = nodemailer.createTransport({
      service: "gmail",
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: "spellbee931@gmail.com",
        pass: "yltkrnhhtfyurhaw",
      },
    });
    var mailOptions = {
      from: "spellbee931@gmail.com",
      to: `${oldUser.email}`,
      subject: "Password Reset",
      text: link,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        res.status(500).json({ message: "error occured", error });
      } else {
        res.status(200).json({ message: "Email sent successfully" });
      }
    });
  } catch (error) {
    res.status(500).json({ message: "internal server error", error });
  }
});

// reset password
app.post("/reset-password/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  const oldUser = await User.findOne({ _id: id });
  if (!oldUser) {
    return res.json({ status: "User Not Exists!!" });
  }
  const secret = process.env.SECRET_KEY + oldUser.password;
  try {
    const verify = jwt.verify(token, secret);

    if (!verify) {
      res.status(500).json({ message: "invalid credentials" });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);
    await User.updateOne(
      {
        _id: id,
      },
      {
        $set: {
          password: encryptedPassword,
        },
      }
    );

    res.status(200).json({
      message: "new password updated successfully",
      newpassword: true,
    });
  } catch (error) {
    res.json({ status: "Something Went Wrong", error });
  }
});
