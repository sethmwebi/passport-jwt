const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
const fs = require("fs");
const fakeLocal = require("./fakeLocal.json");
const bodyParser = require("body-parser");
const path = require("path");
const passport = require("passport");
const localStrategy = require("passport-local").Strategy;
const users = require("./users.json");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const JWTstrategy = require("passport-jwt").Strategy;
const secureRoutes = require("./secureRoutes")

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(bodyParser({ urlencoded: { extended: false } }));
app.use(passport.initialize());
app.use("/user", secureRoutes)

function getJwt() {
  console.log("in getJwt");
  return fakeLocal.Authorization?.substring(7);
}

passport.use(
  new JWTstrategy(
    {
      secretOrKey: "TOP_SECRET",
      jwtFromRequest: getJwt,
    },
    async (token, done) => {
      console.log("in jwt strat. token: ", token);

      if (token?.user?.email === "tokenerror") {
        let testError = new Error(
          "Something bad happened. we've simulated an application error in the JWTstrategy callback for users with an email of 'tokenerror'",
        );
        return done(testError, false);
      }

      if (token?.user?.email === "emptytoken") {
        return done(null, false);
      }
      return done(null, token.user);
    },
  ),
);
passport.use(
  "login",
  new localStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      console.log("login named");
      try {
        if (email === "apperror") {
          throw new Error(
            "Oh no! The application crashed! We have reported the issue. You can change next(error) to next(error.message) to hide the stack trace.",
          );
        }

        const user = users.find((user) => user.email === email);

        if (!user) {
          return done(null, false, { message: "User not found!" });
        }

        const passwordMatches = await bcrypt.compare(password, user.password);

        if (!passwordMatches) {
          return done(null, false, { message: "Invalid credentials!" });
        }

        return done(null, user, {
          message: "Hey congrats! You are logged in!",
        });
      } catch (error) {
        done(error);
      }
    },
  ),
);

passport.use(
  "signup",
  new localStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        if (password.length <= 4 || !email) {
          done(null, false, {
            message: "Your credentials do not match our criteria",
          });
        } else {
          const hashedPass = await bcrypt.hash(password, 10);
          let newUser = { email, password: hashedPass, id: uuidv4() };
          users.push(newUser);
          fs.writeFile("users.json", JSON.stringify(users), (err) => {
            if (err) {
              return done(err);
            }

            console.log("Updated the fake database");
          });
          return done(null, newUser, { message: "Signed up successfully!" });
        }
      } catch (error) {
        return done(error);
      }
    },
  ),
);

app.get("/", (req, res) => {
  res.send("nothing to see here!");
});

app.get(
  "/secureroute",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    console.log("req.isAuthenticated: ", req.isAuthenticated());
    console.log("req.user: ", req.user);
    console.log("req.login: ", req.login);
    console.log("req.logout: ", req.logout);

    res.send(`welcome to the top secret place ${req.user.email}`);
  },
);

app.get("/logout", async (req, res) => {
  fs.writeFile(
    "fakeLocal.json",
    JSON.stringify({ Authorization: "" }),
    (err) => {
      if (err) throw err;
    },
  );
  res.redirect("/login");
});

app.get("/login", async (req, res, next) => {
  res.render("login");
});

app.get("/signup", async (req, res) => {
  res.render("signup");
});

app.get("/failed", async (req, res) => {
  res.send(`failed! ${req.query?.message}`);
});

app.get("/success", (req, res) => {
  res.send(`success ${req.query.message}`);
});

app.post(
  "/login",
  (req, res, next) => {
    passport.authenticate("login", async (error, user, info) => {
      console.log("err: ", error);
      console.log("user: ", user);
      console.log("info: ", info);

      if (error) {
        return next(error.message);
      }

      if (!user) {
        res.redirect(`/failed?message=${info.message}`);
      }

      const body = { _id: user.id, email: user.email };

      const token = jwt.sign({ user: body }, "TOP_SECRET");

      fs.writeFile(
        "fakeLocal.json",
        JSON.stringify({ Authorization: `Bearer ${token}` }),
        (err) => {
          if (err) throw err;
        },
      );

      return res.redirect(`/success?message=${info.message}`);
    })(req, res, next);
  },
  (req, res, next) => {
    res.send("hello");
  },
);

app.post("/signup", async (req, res, next) => {
  passport.authenticate("signup", async (error, user, info) => {
    if (error) {
      return next(error.message);
    }

    if (!user) {
      res.redirect(`/failed?message=${info.message}`);
    }

    const body = { _id: user.id, email: user.email };
    console.log("Body: ", body);
    const token = jwt.sign({ user: body }, "TOP_SECRET");
    fs.writeFile(
      "fakeLocal.json",
      JSON.stringify({ Authorization: `Bearer ${token}` }),
      (err) => {
        if (err) throw err;
      },
    );
    res.redirect(`/success?message=${info.message}`);
  })(req, res, next);
});

app.get("/", (req, res) => {
  res.send("Nothing to see here. Visit create token to create your token.");
});

app.listen(3000, () => {
  console.log("Listening on port 3000");
});
