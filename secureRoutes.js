const express = require("express");
const passport = require("passport");
const router = express.Router();

router.all("*", function(req, res, next) {
  passport.authenticate("jwt", { session: false }, function(err, user, info) {
    console.log("router.all err: ", err?.message);
    console.log("router.all user: ", user);
    console.log("router.all info: ", info?.message);

    if (info) {
      console.log(
        "I happened because the token was either invalid or not present.",
      );
      return res.send(info.message);
    }

    if (err) {
      console.log(
        "I happened because you logged in with the user 'tokenerror' and tried to visit a route that passes through this jwt authentication. We are simulating an application error.",
      );
    }

    if (!user) {
      return res.send(
        "Hm... Not sure what happened. We're simulating an empty/false user being decoded from the token.",
      );
    }

    if (user) {
      console.log("req.login? ", req.login);
      req.isAuthenticated = true;
      req.user = user;
      return next();
    }
  })(req, res, next);
});

router.get("/profile", (req, res, next) => {
  console.log("isAuthenticated: ", req.isAuthenticated)
  console.log("req.user: ", req.user)
  console.log("req.login: ", req.login)
  console.log("req.logout: ", req.logout)
  res.json({
    user: req.user,
    message: "Hello Friend"
  })
})

router.get("/settings", (req, res, next) => {
  res.json({
    user: req.user,
    message: "Settings Page"
  })
})

module.exports = router;
