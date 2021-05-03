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

app.use(session({
	secret: 'awesome auth',
	store: db.SessionStore,
	resave: false,
	saveUninitialized: true
}))


//Security
app.use(passport.initialize())
app.use(passport.session())
const passportConfig = { failureRedirect: '/login'}

const authRequired = (req, res, next) => {
	if (req.user) return next()
	else res.redirect('/login?required=1')
}

app.use((req, res, next) => {
	res.locals.user = req.user
	res.locals.isLoggedIn = (req.user && req.user.phone > 0)
	next()
})



passport.serializeUser((user, cb) => {
	cb(null, user.id)
})

passport.use(new LocalStrategy((phone,password,done) => {
  db.getUserByPhone(phone)
  .then(async (phone) => {
    if (!phone) return done(new Error('등록되지 않은 번호입니다'), false)
    if (!(await db.isPasswordHashVerified(phone.password_hash,password))) return done(new Error('Invalid Password'), false)
    return done(null, phone)
  })
  .catch((err) =>{
    return done(err)
  })
}))

//should change
passport.serializeUser((user,cb) => {
  cb(null, user.id)
})

passport.deserializeUser((id, cb) => {
  db.getUserById(id)
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




// Démarrage du serveur
app.listen(3030, () => {
    console.log("Serveur démarré (http://localhost:3030/ ) !");
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

app.get('/logout', authRequired, (req,res)=>{
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

