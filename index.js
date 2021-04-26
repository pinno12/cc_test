const express = require("express");
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const csurf = require('csurf')
const helmet = require('helmet')
const passport = require('passport')
const LocalStrategy = require('passport-local').LocalStrategy
const db = requrie('./db')(session)
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const crypto = require('crypto');
const app = express();

const nunjucks = require('nunjucks');
nunjucks.configure('views', {
  autoescape: true,
  express: app
});
app.set('view engine', 'html');
app.use(express.static("public"));

//connection to db
const db_name = path.join(__dirname, "data", "apptest.db");
const db = new sqlite3.Database(db_name, err => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connexion réussie à la base de données 'apptest.db'");
});

app.use(session({
  secret: 'awesome chinchin',
  store: db.SessionStore,
  resave: false,
  saveUninitialized: true
}))

//Security
app.use(passport.initialize())
app.use(passport.session())
const passportConfig = { failureRedirectg: '/login'}

const authRequired = (req,res,next) => {
  if(req.user) return next()
  else res.redirect('login?required=1')
}

app.use((req,res,next)=> {
  res.locals.user = req.user
  res.locals.isLoggedIn = (req.user && req.user.uid > 0)
  next()
})

//Username 바꾸기
passport.use(new LocalStrategy((username,password,done) => {
  db.getUserByUsername(username)
  .then(async (user) => {
    if (!user) return done(new Error('등록되지 않은 번호입니다'), false)
    if (!(await db.isPasswordHashVerified(user.password_hash,password))) return done(new Error('Invalid Password'), false)
    return done(null, user)
  })
  .catch((err) =>{
    return done(err)
  })
}))

//should change
passport.serializeUser((user,cb) => {
  cb(null, user.uid)
})

passport.deserializeUser((uid, cb) => {
  db.getUserById(uid)
  .then((user)=>{
    cb(null,user)
  })
  .catch((err) => {
    cb(err,null)
  })
})


// Création de la table Livres (Livre_ID, Titre, Auteur, Commentaires)
const sql_create = `CREATE TABLE IF NOT EXISTS Livres (
  Livre_ID INTEGER PRIMARY KEY AUTOINCREMENT,
  Titre VARCHAR(100) NOT NULL,
  Auteur VARCHAR(100) NOT NULL,
  Commentaires TEXT
);`;

const sql_
db.run(sql_create, err => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Création réussie de la table 'Livres'");
  // Alimentation de la table
  const sql_insert = `INSERT INTO Livres (Livre_ID, Titre, Auteur, Commentaires) VALUES
  (1, 'Mrs. Bridge', 'Evan S. Connell', 'Premier de la série'),
  (2, 'Mr. Bridge', 'Evan S. Connell', 'Second de la série'),
  (3, 'L''ingénue libertine', 'Colette', 'Minne + Les égarements de Minne');`;
  db.run(sql_insert, err => {
    if (err) {
      return console.error(err.message);
    }
    console.log("Alimentation réussie de la table 'Livres'");
  });
});

// Démarrage du serveur
app.listen(3000, () => {
    console.log("Serveur démarré (http://localhost:3000/ ) !");
});

// GET /
app.get("/", (req, res) => {
  // res.send("Bonjour le monde...");
  res.render("index.html");
});

// GET /about
app.get("/about", (req, res) => {
  res.render("about");
});

app.get("/subscribe", (req, res) => {
  res.render("subscribe");
});

// GET /data
app.get("/data", (req, res) => {
  const test = {
    titre: "Test",
    items: ["un", "deux", "trois"]
  };
  res.render("data", { model: test });
});

// GET /livres
app.get("/livres", (req, res) => {
  const sql = "SELECT * FROM Livres ORDER BY Titre";
  db.all(sql, [], (err, rows) => {
    if (err) {
      return console.error(err.message);
    }
    res.render("livres", { model: rows });
  });
});

// GET /create
app.get("/create", authRequired, (req, res) => {
  res.render("create", { model: {} });
});

// POST /create
app.post("/create", (req, res) => {
  const sql = "INSERT INTO Livres (Titre, Auteur, Commentaires) VALUES (?, ?, ?)";
  const book = [req.body.Titre, req.body.Auteur, req.body.Commentaires];
  db.run(sql, book, err => {
    if (err) {
      return console.error(err.message);
    }
    res.redirect("/livres");
  });
});

// function hashPassword(password, salt) {
//   var hash = crypto.createHash('sha256');
//   hash.update(password);
//   hash.update(salt);
//   return hash.digest('hex');
// }

// passport.use(new LocalStrategy(function(username, password, done) {
//   db.get('SELECT salt FROM users WHERE username = ?', username, function(err, row) {
//     if (!row) return done(null, false);
//     var hash = hashPassword(password, row.salt);
//     db.get('SELECT username, id FROM users WHERE username = ? AND password = ?', username, hash, function(err, row) {
//       if (!row) return done(null, false);
//       return done(null, row);
//     });
//   });
// }));

app.all('/login', (req,res,next) => {
  new Promise((resolve, reject) => {
    if(req.method === 'GET') {return reject()}
    if(req.body.phone && req.body.password){
      passport.authenticate('local', (err,user, info)=>{
        if(!err && user){
          return resolve(user)
        }
        reject(err)
      })(req,res,next)
    }
else{
  reject(new Error('다 채워주세요'))
}
})
.then(user => new Promise((resolve, reject)=> {
  req.login(user,err => {
    if(err) return reject(err)
    console.log('auth completed', user)
    res.redirect('/')
  })
}))
.catch(error => {
  let errorMsg = (error&& error.message ) || ''
  if (!error && req.query.required) errorMsg = '다시 로그인해주세요'

  res.render('login', {
    csrfToken: req.csrfToken(),
    hasError: (errorMsg && errorMsg.length > 0), 
    error, errorMsg,
    form: req.body
  })

  })
})

app.all('/register', (req,res) => {
  new Promise(async (resolve, reject) => {
    if (Object.keys(req.body)>0){
      if (
        !(req.body.email && req.body.email.length > 3)
      || !(req.body.password && req.body.password.length> 4)
      ){
        reject('입력한 것을 다시 확인해 주세요')
      }
      else{
        resolve(true)
      }
    }
    else{
      resolve(false)
    }
    
  })
  .then(isValidFormData => new Promise((resolve, reject) => {
    if(Object.keys(req.body).length>0 && isValidFormData){
      db.createUserRecord({
        username: req.body.username,
        phone: req.body.phone,
        passwrod: req.body.password
      })
      .then((createdUser) => {
        resolve(createdUser)
      })
      .catch(err => reject(err))
    }
    else{
      resolve(false)
    }
  }))
  .then((createdUserRecord)=>{
    if (createdUserRecord){
      req.login(createdUserRecord, (err) => {
        console.log(err)
      })
      res.render('회원 가입이 되었습니다')
    }
    else{
      res.render('register', {
        csrfToken: req.csrfToken(),
        hasError: false,
        form: req.body
      })
    }
  })
  .catch((error)=>{
    res.render('register',{
      csrfToken: req.csrfToken(),
      hasError: true,
      error,
      form: req.body
    })
  })
})

get('/logout', authRequired, (req,res)=>{
  req.logout()
  res.render('/')
})
// GET /edit/5
app.get("/edit/:id", (req, res) => {
  const id = req.params.id;
  const sql = "SELECT * FROM Livres WHERE Livre_ID = ?";
  db.get(sql, id, (err, row) => {
    if (err) {
      return console.error(err.message);
    }
    res.render("edit", { model: row });
  });
});

// POST /edit/5
app.post("/edit/:id", (req, res) => {
  const id = req.params.id;
  const book = [req.body.Titre, req.body.Auteur, req.body.Commentaires, id];
  const sql = "UPDATE Livres SET Titre = ?, Auteur = ?, Commentaires = ? WHERE (Livre_ID = ?)";
  db.run(sql, book, err => {
    if (err) {
      return console.error(err.message);
    }
    res.redirect("/livres");
  });
});

// GET /delete/5
app.get("/delete/:id", (req, res) => {
  const id = req.params.id;
  const sql = "SELECT * FROM Livres WHERE Livre_ID = ?";
  db.get(sql, id, (err, row) => {
    if (err) {
      return console.error(err.message);
    }
    res.render("delete", { model: row });
  });
});

// POST /delete/5
app.post("/delete/:id", (req, res) => {
  const id = req.params.id;
  const sql = "DELETE FROM Livres WHERE Livre_ID = ?";
  db.run(sql, id, err => {
    if (err) {
      return console.error(err.message);
    }
    res.redirect("/livres");
  });
});
