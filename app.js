require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();


app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret:"Our little lund",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGO_URI,{useNewUrlParser:true});

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:[{
        type:String
    }]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User",userSchema); 

passport.use(User.createStrategy());
passport.serializeUser(function(user,done){
    done(null, user.id);
});
passport.deserializeUser(async (id,done)=>{
   try{
    const user = await User.findById(id);
    if(!user) throw new Error('User not found');
    // console.log(user);
    done(null,user);
   }catch(err){
     console.log(err);
     done(err,null);
   }
});
    


passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL:"http://localhost:3000/auth/google/secrets"
},
function(accessToken,refreshToken,profile,cb){
    User.findOrCreate({username:profile.emails[0].value,googleId:profile.id},function(err,foundUser){
        if(!err){
            if(foundUser){
                return cb(null,foundUser);
            }else{
                const newUser=new User({
                    username:profile.emails[0].value,
                    googleId:profile.id
                });
                newUser.save(function(err){
                    if(!err){
                        return cb(null,newUser);
                    }
                })
            }
        }else{
            console.log(err);
        }
    })
}
))



app.get('/',(req,res)=>{
    res.render('home');
})
app.get('/auth/google',
       passport.authenticate('google',{scope:['profile','email']})
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get('/login',(req,res)=>{
    res.render('login');
})
app.get('/register',(req,res)=>{
    res.render('register');
})
app.get('/secrets',async (req,res)=>{
    const userData=await User.find({"secret":{$ne:null}});
    console.log(userData);
    res.render('secrets',{userWithsecrets:userData});
})
app.get('/submit',(req,res)=>{
    if(req.isAuthenticated()){
        return res.render('submit');
    }else{
       return res.redirect('/login');
    }

})

app.post('/submit',async(req,res)=>{
    const submittedSecret = req.body.secret;
    const a=req.user;

    const data=await User.findById(a._id);
    data.secret.push(submittedSecret);
    await data.save();
    console.log(data.secret.length);
    res.redirect('/secrets');
})

app.post('/register',async(req,res)=>{
    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            return res.redirect('/register');
        }else{
            passport.authenticate('local')(req,res,function(){
                return res.redirect('/secrets');
            })
        }
    })
})

app.post('/login',async(req,res)=>{
    const user = new User({
        username:req.body.username,
        password:req.body.password
    });
    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate('local')(req,res,function(){
                return res.redirect('/secrets');
            })
        }
    })
})

app.get('/logout',(req,res)=>{
    req.logout(function(err){
        if(err){
            console.log(err);
        }else{
            res.redirect('/');
        }
    });
    
})


app.listen(process.env.PORT||3000,(req,res)=>{
    console.log('Server is running');
})
