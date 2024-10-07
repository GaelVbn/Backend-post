import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import User from "./Schema/User.js";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";

import { readFile } from "fs/promises";

const serviceAccountKey = JSON.parse(
  await readFile(
    new URL(
      "./anitaposts-d2d2e-firebase-adminsdk-fn7z9-d0e5463859.json",
      import.meta.url
    )
  )
);

const server = express();
let PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

// setting up s3 bucket
const s3 = new aws.S3({
  region: "eu-north-1",
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const generateUploadURL = async () => {
  const date = new Date();
  const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

  return await s3.getSignedUrlPromise("putObject", {
    Bucket: "anitaposts",
    Key: imageName,
    Expires: 1000,
    ContentType: "image/jpeg",
  });
};

const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};
const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let isUsernameNotUnique = await User.exists({
    "personnal_info.username": username,
  }).then((result) => result);

  isUsernameNotUnique ? (username += nanoid().substring(0, 5)) : "";

  return username;
};

// upload image url route

server.get("/get-upload-url", (req, res) => {
  generateUploadURL()
    .then((url) => res.status(200).json({ uploadURL: url }))
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json(err.message);
    });
});

server.post("/signup", (req, res) => {
  const { fullname, email, password } = req.body;

  //validating the data from the front
  if (fullname.length < 3) {
    return res.status(403).json("error: fullname must be 3 letters long");
  }
  if (!email.length) {
    return res.status(403).json("error: email is required");
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json("error: invalid email");
  }
  if (!passwordRegex.test(password)) {
    return res
      .status(403)
      .json(
        "error: password should be at least 6 to 20  characters long with a numeric, 1 lower and 1 uppercase letter"
      );
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let username = await generateUsername(email);

    let user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_password,
        username,
      },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(500).json("error: email already exists");
        }
      });

    console.log(hashed_password);
  });
});

server.post("/signin", (req, res) => {
  let { email, password } = req.body;
  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json("error: email not found");
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(403).json(err.message);
          }

          if (!result) {
            return res.status(403).json("error: invalid password");
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      } else {
        return res
          .status(403)
          .json(
            "error: Account was created using google. try logging in with google."
          );
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(403).json(err.message);
    });
});

server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;

      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json(err.message);
        });

      if (user) {
        if (!user.google_auth) {
          return res.status(403).json({
            error:
              "this email was signed up without google. Please log in with password to access the account.",
          });
        }
      } else {
        let username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            profile_img: picture,
            username,
          },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json(err.message);
          });
      }

      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      return res
        .status(500)
        .json(
          "error : failed to authenticate you with google. Try with some other google account."
        );
    });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
