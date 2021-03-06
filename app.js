require('dotenv').config();
const express = require('express')
const bodyParser = require('body-parser')
require('./db/mongoose')
const mongoose = require('mongoose');
const { urlencoded } = require('body-parser')
const session = require('express-session')
const passport = require('passport')
const passportLocalMongoose = require('passport-local-mongoose')
const GoogleStrategy = require('passport-google-oauth20').Strategy
const findOrCreate = require('mongoose-findorcreate')
const FacebookStrategy = require('passport-facebook').Strategy
 
const app = express()
const port = 3000 || process.env.PORT

app.set('view engine', 'hbs')
app.use(express.urlencoded({ extended: true }));

// configure the session     https://www.npmjs.com/package/express-session
app.use(session({
    secret: 'my secret',
    resave: false,
    saveUninitialized: false
    // cookie: { secure: true }
}))

app.use(passport.initialize())
app.use(passport.session())

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String
})

//hash salt the password and save user to mongodb database
userSchema.plugin(passportLocalMongoose) 
userSchema.plugin(findOrCreate) 

const User = new mongoose.model("User", userSchema)

// simplify LocalStrategy with passport        https://www.npmjs.com/package/passport-local-mongoose
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
});
  
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/welcome"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_ID,
    clientSecret: process.env.FACEBOOK_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/welcome"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
 
app.get('/', (req, res) => {
    res.render('index');
});

app.get('/auth/google',
    passport.authenticate("google", { scope: ['profile'] })
);  

app.get('/auth/google/welcome', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/welcome');
});


app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/welcome',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/welcome');
});


app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register'); 
});

app.get("/logout", (req, res) => {
    req.logout()
    res.redirect("/")

})

app.get("/welcome", (req, res) => {
    if(req.isAuthenticated()){
        res.render("welcome")
    }else{
        res.redirect("/login")
    }
})

app.post("/register", (req,res) => {
    //the methode register came from passport-local-mongoose    https://www.npmjs.com/package/passport-local-mongoose
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register")
        }else{ 
            passport.authenticate("local")(req, res, function(){
                res.redirect("/welcome")
            })
        }    
    })
})

app.post('/login', (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/welcome")
            })
            
        }
    })
    
});

app.listen(port, ()=> {
    console.log("app listen on port: " + port);
})