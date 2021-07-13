const express = require('express')
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require('body-parser')

const cookieParser = require('cookie-parser')
const session = require('express-session')
var csrf = require('csurf')
const helmet = require('helmet')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const db = require('./db')(session)
const model = require('./db')
const PORT = process.env.PORT || 4008
const db_name = path.join(__dirname, "data", "apptest.db");
const dbS = new sqlite3.Database(db_name, err => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connexion réussie à la base de données 'apptest.db'");
});
// express app
const app = express()

const nunjucks = require('nunjucks');
app.engine('html', nunjucks.render);
app.set('view engine', 'html');
nunjucks.configure('views', {
  autoescape: true,
  express: app
});
app.set("views", path.join(__dirname, "views"));

app.use(cookieParser())
app.use(express.static('public'))
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.use(session({
	secret: 'awesome auth',
	store: db.SessionStore,
	resave: false,
	saveUninitialized: true,
	cookie           : {
		httpOnly         : true,
		resave           : false,
		saveUninitialized: false,
		maxAge           : 7776000 * 1000
	}	
}
))

// setup route middlewares
var csrfProtection = csrf({ cookie: true })
var parseForm = bodyParser.urlencoded({ extended: false })

	
app.use(cookieParser())


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

passport.use(new LocalStrategy({
	usernameField: 'phone',
    passwordField: 'password'
  },
	(username, password, done) => {
	db.getUserByphone(username)
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
/* Routes */
app.get("/", authRequired, (req, res) => {
	// let params= [req.session.user_phone, req.session.user_phone];
	// const sql = "SELECT * FROM solos INNER JOIN users ON users.phone = solos.user_phone WHERE ( user_phone in ((SELECT friend_phone FROM friends WHERE user_phone = ?) or (SELECT user_phone FROM friends WHERE friend_phone = ?)) or user_phone =  ? )";

	let params= [req.session.user_phone, req.session.user_phone, req.session.user_phone];
	const sql = "SELECT * FROM solos INNER JOIN users ON users.phone = solos.user_phone WHERE (( user_phone in (SELECT friend_phone FROM friends WHERE user_phone = ? UNION ALL SELECT user_phone FROM friends WHERE friend_phone = ?) or user_phone =  ? ))";
	dbS.all(sql, params, (err, result) => {
	  if (err) {
		return console.error(err.message);
	  }
	//   console.log(result)
	  res.render("index", { solo : result,
		user_phone: req.session.user_phone 
	});
	});
  });

app.get("/about", (req, res) => {
	res.render("about");
  });
  

  app.get("/subscribe", authRequired,(req, res) => {
	res.render("subscribe", { 
		user_phone: req.session.user_phone
	});
  });

  app.get("/solo",authRequired, (req, res) => {
	  console.log(db.SoloModel)
	res.render("solo", { 
		user_phone: req.session.user_phone
	});
  });
  app.post('/solo', function(req, res) {
	var post = req.body;
	let solo =  {pros: req.body.pros, age: req.body.age, gender: req.body.gender,
	cons: req.body.cons,
	muze: post.muze,
	etc: post.etc,
	is_solo: post.is_solo,
	user_phone: req.session.user_phone
  }
	db.SoloModel.create(solo)
	 .then( res => {
		console.log(solo,"데이터 추가 완료");          
	  })
	  .catch( err => {
		console.log("데이터 추가 실패");
		res.send("입력란에 문제가 있습니다:<");
	  })	
	  res.render('solo', { 
		user_phone: req.session.user_phone
	});
  });




app.get('/member', authRequired, (req, res) => {
	res.render('member')
})
app.get("/myfriends",authRequired, (req, res) => {
	params =  [req.session.user_phone, req.session.user_phone]
	let sql = "select * from friends where user_phone = ? UNION ALL SELECT * FROM friends WHERE friend_phone = ?"
	dbS.all(sql,params,(err,result)=>{
		if (err) {
			return console.error(err.message);
		  }
		  res.render("myfriends", { friends: result,
			user_phone: req.session.user_phone
		});
	})
  
});

app.post('/myfriends', authRequired, (req, res) => {
	let params= [req.session.user_phone, req.body.friend_phone, req.body.friend_name];	
	// const sql = "SELECT uid	FROM users 	WHERE phone = ?";
	let sql = "INSERT INTO friends (user_phone, friend_phone, friend_name) VALUES (? , ?, ?)"

	  dbS.all(sql, params, (err, result) => {
		if (err) {
		  return console.error(err.message);
		}
		params2 =  [req.session.user_phone]
		let sql2 = "select * from friends where user_phone = ? "
		dbS.all(sql2,params2,(err,result)=>{
			if (err) {
				return console.error(err.message);
			  }
			  res.render("myfriends", { friends: result,
				user_phone: req.session.user_phone
			});
		})

	  });
	
	});


app.all('/login', (req, res, next) => {
	new Promise((resolve, reject) => {
		if (req.method === 'GET') { return reject() }
		if (req.body.phone && req.body.password) {
			console.log(req.body.phone)
			passport.authenticate('local', (err, user, info) => {
				if (!err && user) {			
					return resolve(user)
				}
				reject(err)
			})(req, res, next)
		}
		else {
			reject(new Error('Please fill all fields'))
		}
	})
		.then(user => new Promise((resolve, reject) => {
			req.login(user, err => { // save authentication
				if (err) return reject(err)
				req.session.user_phone = user.phone;
				req.session.user_id = user.uid;
				
				console.log(req.session.user_phone, 'auth completed - redirecting to member area')
				// return res.send('<script>location.href="/member";</script>')
				return res.redirect('/')
			})
		}))
		.catch(error => {
			let errorMsg = (error && error.message) || ''
			if (!error && req.query.required) errorMsg = '로그인해주세요'

			res.render('login', {
				// csrfToken: req.csrfToken(),
				// hasError: (errorMsg && errorMsg.length > 0),
				// error: errorMsg,
				form: req.body,
			})
		})
})

app.all('/register', (req, res) => {
	new Promise(async (resolve, reject) => {
		if (Object.keys(req.body).length > 0) {
			if (
				!(req.body.phone && req.body.phone.length >= 1)		
				|| !(req.body.password && req.body.password.length >= 1)			
			) {
				reject('다 채워라잉')
			}
			else if (await db.isphoneInUse(req.body.phone)) {
				reject('친구, 이미 가입했소')
			}		
			else {
				resolve(true)
			}
		}
		else {
			resolve(false)
		}
	})
		.then(isValidFormData => new Promise((resolve, reject) => {
			if (Object.keys(req.body).length > 0 && isValidFormData) {
				db.createUserRecord({
					phone: req.body.phone,
					password: req.body.password,
					name: req.body.username
				})
					.then((createdUser) => {
						// console.log('====> user created...')
						// console.log(creationSuccessful)
						// authenticate?
						resolve(createdUser)
					})
					.catch(err => reject(err))
			}
			else {
				resolve(false)
			}
		}))
		.then((createdUserRecord) => {
			if (createdUserRecord) {

				// Log them in in the session
				req.login(createdUserRecord, (err) => {
					console.log(err)
				})
				res.render('login')
			}
			else {
				res.render('register', {
					form: req.body
				})
			}
		})
		.catch((error) => {
			// console.log(error)
			res.render('register', {

				error,
				form: req.body
			})
		})
})

app.get('/logout', authRequired, (req, res) => {
	req.logout()
	return res.redirect('login')
})


// App start
app.listen(PORT, () => console.log(`App listening on port http://localhost:${PORT} !`))
