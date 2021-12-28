require("dotenv").config();

const express = require("express");
const session = require("express-session");
const app = express();
const cors = require("cors");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const cookieParser = require("cookie-parser");
const port = process.env.PORT || 3001;
const secreto = "patata";
const crypto = require("crypto");

const mongodb = require("mongodb");
const MongoClient = mongodb.MongoClient;
const MongoStore = require("connect-mongo");

let feedback = {
  //provee de feedback específico sobre el fallo en la autentificación
  middle: true,
  provider: true, // true = específico, false = genérico
  mensaje: "Login correcto",
};

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(
  session({
    secret: secreto, //Secreto de la sesion (se puede hacer dinámico),
    resave: false, //Evita el reseteo de la sesión con cada llamada
    saveUninitialized: false, //Evita crear sesiones vacías
    store: MongoStore.create({
      //Nos guarda las sesiones en la colección "sesiones" en la base de datos "prueba"
      mongoUrl: process.env.URL_MONGO,
      dbName: "Searcher",
      collectionName: "sesiones",
      ttl: 1000 * 60 * 60 * 24, //Time To Live de las sesiones
      autoRemove: "native", //Utiliza el registro TTL de Mongo para ir borrando las sesiones caducadas.
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, //Caducidad de la cookie en el navegador del cliente.
    },
  })
);
app.use(cookieParser(secreto));
app.use(passport.initialize());
app.use(passport.session());

if (feedback.middle) {
  app.use((req, res, next) => {
    console.log("Express Middleware");
    console.log(req.session ? req.session : "No hay sesion");
    console.log(req.user ? req.user : "No hay usuario");
    next();
  });
}

MongoClient.connect(
  process.env.URL_MONGO,
  { useUnifiedTopology: true },
  function (error, client) {
    error
      ? (console.log("🔴 MongoDB no conectado"),
        console.log("error: "),
        console.log(error))
      : ((app.locals.db = client.db("Searcher")),
        console.log("🟢 MongoDB conectado"));
  }
);

passport.use(
  new LocalStrategy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    function (email, password, done) {
      console.log(password);
      feedback.mensaje = "";
      app.locals.db
        .collection("users")
        .findOne({ email: email }, function (err, user) {
          if (err) {
            return done(err);
          }
          if (!user) {
            feedback.provider
              ? (feedback.mensaje = "Usuario no registrado")
              : (feedback.mensaje = "Login erróneo");
            return done(null, false);
          }
          if (!validoPass(password, user.password.hash, user.password.salt)) {
            feedback.provider
              ? (feedback.mensaje = "Password incorrecto")
              : (feedback.mensaje = "Login erróneo");
            return done(null, false);
          }
          feedback.mensaje = "Login correcto";
          return done(null, user);
        });
    }
  )
);

passport.serializeUser(function (user, done) {
  console.log("-> Serialize");
  done(null, user);
});

passport.deserializeUser(function (user, done) {
  console.log("-> Deserialize");
  app.locals.db
    .collection("users")
    .findOne({ email: user.email }, function (err, usuario) {
      if (err) {
        return done(err);
      }
      if (!usuario) {
        return done(null, null);
      }
      return done(null, usuario);
    });
});

// _____________________________________________________________________RUTAS
// __________________________________________________Gestion

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/api",
    failureRedirect: "/api/fail",
  })
);

app.all("/api", (req, res) => {
  res.send({
    logged: true,
    mensaje: feedback.mensaje,
    user: req.user,
  });
});

app.all("/api/fail", (req, res) => {
  res.send({
    logged: false,
    mensaje: "Login incorrecto",
  });
});

app.post("/logout", (req, res) => {
  req.logOut(),
    res.send({
      logged: false,
      mensaje: "Logout correcto",
    });
});

//_____________________________________________Utilidad

app.post("/signup", (req, res) => {
  req.app.locals.db
    .collection("users")
    .find({ email: req.body.email })
    .toArray((err, users) => {
      if (err) {
        res.send({ error: true, contenido: err });
      } else {
        if (users.length > 0) {
          res.send({ error: true, mensaje: "El usuario ya está registrado" });
        } else {
          let passwordCrypt = creaPass(req.body.password);
          req.app.locals.db.collection("users").insertOne(
            {
              email: req.body.email,
              password: { hash: passwordCrypt.hash, salt: passwordCrypt.salt },
              favoritos: [],
            },
            (err1, data) => {
              err1
                ? res.send({ error: true, contenido: err1 })
                : res.send({
                    error: false,
                    contenido: data,
                    mensaje: "Usuario registrado correctamente",
                  });
            }
          );
        }
      }
    });
});

app.put("/user", (req, res) => {
  console.log(req.body);
  req.app.locals.db
    .collection("users")
    .updateOne(
      { email: req.body.email },
      { $set: { favoritos: req.body.favoritos } },
      function (error, datos) {
        error
          ? res.send({
              error: true,
              contenido: error,
              mensaje: "No se ha podido modificar",
            })
          : res.send({
              error: false,
              contenido: datos,
              mensaje: "Modificado correctamente",
            });
      }
    );
});

app.get("/perfil", (req, res) => {
  req.isAuthenticated()
    ? res.send({
        logged: true,
        mensaje: "Todo correcto: Esto es información confidencial",
        user: req.user,
      })
    : res.send({
        looged: false,
        mensaje: "Necesitas loguearte",
      });
});

app.get("/info", (req, res) => {
  req.isAuthenticated()
    ? res.send({
        logged: true,
        mensaje: "Todo correcto: Esto es información confidencial",
        user: req.user,
      })
    : res.send({
        looged: false,
        mensaje: "Necesitas loguearte",
      });
});

app.listen(port, (err) => {
  err
    ? console.error("🔴 Servidor fallido")
    : console.log("🟢 Servidor a la escucha en el puerto:" + port);
});

function creaPass(password) {
  let salt = crypto.randomBytes(32).toString("hex");
  let genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return {
    salt: salt,
    hash: genHash,
  };
}

function validoPass(password, hash, salt) {
  let hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hashVerify === hash;
}
