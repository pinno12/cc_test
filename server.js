const express = require("express");
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const csurf = require('csurf')
const helmet = require('helmet')
const passport = require('passport')
// const LocalStrategy = require('passport-local').LocalStrategy
var LocalStrategy   = require('passport-local').Strategy
const db = require('./routes/db')(session)
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const crypto = require('crypto');
const app = express();
  app.use(helmet());
require('dotenv').config()

// ES6 Module loader
require = require('esm')(module)
const nunjucks = require('nunjucks');
nunjucks.configure('views', {
  autoescape: true,
  express: app
});
app.set('view engine', 'html');
app.use(express.static("public"));

//connection to db
const db_name = path.join(__dirname, "data", "apptest.db");
// const db = new sqlite3.Database(db_name, err => {
//   if (err) {
//     return console.error(err.message);
//   }
//   console.log("Connexion réussie à la base de données 'apptest.db'");
// });

app.use(session({
	secret: 'awesome auth',
	store: db.SessionStore,
	resave: false,
	saveUninitialized: true
}))

// security
const csrf = csurf({ cookie: true })
app.use(helmet())
app.use(csrf)
app.use((err, req, res, next) => {
	if (err.code !== 'EBADCSRFTOKEN') return next(err)
	res.status(403).render('error', { message: 'Invalid form submission!' })
})

// passport
app.use(passport.initialize())
app.use(passport.session())
const passportConfig = { failureRedirect: '/login' }

const authRequired = (req, res, next) => {
	if (req.user) return next()
	else res.redirect('/login?required=1')
}

app.use((req, res, next) => {
	res.locals.user = req.user
	res.locals.isLoggedIn = (req.user && req.user.uid > 0)
	next()
})

passport.use(new LocalStrategy((username, password, done) => {
	db.getUserByUsername(username)
		.then(async (user) => {
			if (!user) return done(new Error('User not found!'), false)
			if (!(await db.isPasswordHashVerified(user.password_hash, password))) return done(new Error('Invalid Password'), false)
			return done(null, user)
		})
		.catch((err) => {
			return done(err)
		})
}))

passport.serializeUser((user, cb) => {
	cb(null, user.uid)
})

passport.deserializeUser((uid, cb) => {
	db.getUserById(uid)
		.then((user) => {
			cb(null, user)
		})
		.catch((err) => {
			cb(err, null)
		})
})


// GET /
app.get("/", (req, res) => {
  res.send("Bonjour le monde...");
  // res.render("register.html");
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
			let errorMsg = (error && error.message) || ''
			if (!error && req.query.required) errorMsg = 'Authentication required'

			res.render('login', {
				csrfToken: req.csrfToken(),
				hasError: (errorMsg && errorMsg.length > 0),
				error: errorMsg,
				form: req.body,
			})
		})
})

app.all('/register', (req,res) => {
  new Promise(async (resolve, reject) => {
    if (Object.keys(req.body)>0){
      if (
        !(req.body.phone && req.body.phone.length > 3)
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

app.get('/logout', authRequired, (req,res)=>{
  req.logout()
  res.render('/')
  // return res.send('<script>location.href="/";</script>')
})

app.listen(3000, () => {
    console.log("Serveur démarré (http://localhost:3000/ ) !");
});