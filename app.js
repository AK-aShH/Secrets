
require("dotenv").config(); // to keep secrets save using environment variables
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');
const md5 = require('md5');  // for hashing our passwords but its too fast which can benefit hackers
const bcrypt = require('bcrypt'); // for hashing passwords but comparitively slow and hence secure
const saltRounds = 10;

const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

// Google autherisation Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// Package to import findOrcreate function in mongoose which is by default not a mongoose method
const findOrCreate = require('mongoose-findorcreate');

// Facebook autherisation Strategy
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// For initialsing and setting up session we use it here only after all app.use statments and before database connection
app.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}));

// TO initialize passport and use session
app.use(passport.initialize());
app.use(passport.session());

// Database Connection
mongoose.connect(process.env.MONGODB_URL, function(err) {
    if (err) {
        console.log(err);
        } else {
            console.log('Connected to Database!');
            }
});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: [String]
});

// Now to setup and use our passport-local-mongooose plugin we do it here -
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate); //plugin for findorcreate 


const secret=process.env.SECRET;
// userSchema.plugin(encrypt, { secret: secret, excludeFromEncryption: ['email'] });

const User = mongoose.model('User', userSchema);

// Configure passport-local and passport, after our model User

// Strategies are responsible for authenticating requests, which they accomplish by implementing an authentication mechanism.
passport.use(User.createStrategy());              // Creates LocalStrategy (named "local") for passport authentication using the passport-local module and used by passport module.

// passport.serializeUser(User.serializeUser());     // Serialise sessions with local strategy authentication
// passport.deserializeUser(User.deserializeUser()); //deserialize sessions with local strategy authentication

// Now since we are using google strategy authentication we need to serialize and deserialize sessions that works for all, So--
passport.serializeUser(function(user, done){
    done(null, user.id);
});

passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user);
    });
});

// configuring Google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secret-fjord-40878.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) { // gets called when the user is authenticated successfully by google

    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// configuring Facebook strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "https://secret-fjord-40878.herokuapp.com/auth/facebook/secrets",
    },
    function(accessToken, refreshToken, profile, cb) { // gets called when the user is authenticated successfully by facebook
    
        console.log(profile);
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    })
);


app.get("/", (req, res) => {
    res.render("home");
});

// route which authenticate the user after cliclking sign in with google
// After this we setup are callback route(/auth/google/secrets) to authenticate the user locally on our website and save their login session using cookies and sessions so that we can autheroize him for all authentication required pages
app.get('/auth/google', 
passport.authenticate('google', { scope: ['profile'] })); // initiate authentication on google servers asking for user's profile

// requested by google to authenticate locally
app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }), function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/auth/facebook', 
passport.authenticate('facebook', { scope: ['profile'] })); // initiate authentication on facebook servers asking for user's profile

// requested by facebook to authenticate locally
app.get('/auth/facebook/secrets', passport.authenticate('google', { failureRedirect: '/login' }), function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});



app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", function(req, res){
   User.find({secrets: { $exists: true, $type: 'array', $ne: [] }},function(err, users){
    if(err){
        console.log(err);
    }else
    if(users){
        res.render("secrets",{userswithSecrets: users})
    }
   });
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated){ //if the request to access secrets is lareasy authenticated then allow else redirect to login
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.get("/logout", function(req, res){
    req.logout(function(err) {
        if (err) {
            console.log(err); 
        }else{
            res.redirect('/');
        }
      });
});

app.post("/register", function(req, res){

    // Using cookies and sessions through passpost and passport-local-mongoose module
    User.register({username: req.body.username}, req.body.password,function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, function(){ // this middleware invokes req.login() to login the newly registered automatically and also creates the cookie with the session
                res.redirect("/secrets");
            });
        }
    });



    // Using bcrypt hashing only and not cookies and sessions
    // bcrypt.hash(myPlaintextPassword, saltRounds, function(err, hash) {
    //     // Store hash in your password DB.
    //     const user = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    //     user.save(function(err){
    //         if(err){
    //             console.log(err);
    //         }else{
    //             res.render("secrets");
    //         }
    //     });
    
    // });
    
});

app.post("/login", function(req, res){
    // Bcrypt hashing
    // const email = req.body.username;
    // const password= req.body.password;
    // User.findOne({email:email}, function(err, foundUser){
    //     if(!err){
    //         bcrypt.compare(password, foundUser.password, function(err, result) {
    //             // result == true
    //             if(result===true){
    //                 res.render("secrets");
    //             }
    //         });
    //     }else{
    //         console.log(err);
    //     }
    // })


    // using cookies and sessions

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){ // this middleware invokes req.login() to login the newly registered automatically and also creates the cookie with the session
                res.redirect("/secrets"); //creates the cookie for the session to allow user to access all pages that requires authentication
            });
        }
    });
});

app.post("/submit", function(req, res){
    const newSecret = req.body.secret;
    console.log(req.user); // passport.authenticate when authenctication succeeds, set a "req.user" property to the authenticated user to get all the properties of current user
    User.findById(req.user.id,function(err, user){
        if(err){
            console.log(err);
        }else
        if(user){
            user.secrets.push(newSecret);
            user.save(function(){
                res.redirect("/secrets");
            });
        }
    });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server started on port 3000');
    }   
);

