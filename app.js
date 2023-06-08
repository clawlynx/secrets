require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_CONNECTION_STRING);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: Array,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

// google strategy//
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// facebook strategy//
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FB_APP_ID,
      clientSecret: process.env.FB_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

//routes//

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/secrets", function (req, res) {
  res.set(
    "Cache-Control",
    "no-cache, private, no-store, must-revalidate, max-stal, e=0, post-check = 0, pre-check = 0"
  );
  if (req.isAuthenticated()) {
    findall();
    async function findall() {
      try {
        const allUsers = await User.find({ secret: { $ne: null } });
        res.render("secrets", { allTheSecrets: allUsers });
      } catch (error) {
        res.send(error);
      }
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", function (req, res) {
  res.set(
    "Cache-Control",
    "no-cache, private, no-store, must-revalidate, max-stal, e=0, post-check = 0, pre-check = 0"
  );
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res, next) {
  req.logOut(function (error) {
    if (error) {
      return next(error);
    }
    res.redirect("/");
  });
});

app.post("/register", async function (req, res) {
  try {
    const userRegister = await User.register(
      { username: req.body.username },
      req.body.password
    );
    if (userRegister) {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    } else {
      res.redirect("/register");
    }
  } catch (error) {
    res.send(error);
  }
});

app.post("/login", passport.authenticate("local"), function (req, res) {
  const userRegister = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(userRegister, function (error) {
    if (error) {
      console.log(error);
    } else {
      res.redirect("/secrets");
    }
  });
});

app.post("/submit", async function (req, res) {
  try {
    const newSecret = req.body.secret;
    console.log(req.user);
    const currentUser = await User.findById(req.user.id);
    if (currentUser == null) {
      const currentUsernew = await User.findOne({
        username: req.user.username,
      });
      currentUsernew.secret = newSecret;
      await currentUsernew.save();
      res.redirect("/secrets");
    } else {
      currentUser.secret = newSecret;
      await currentUser.save();
      res.redirect("/secrets");
    }
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

app.listen(process.env.PORT || 3000, function () {
  console.log("successfully connected to server");
});
