const bcrypt = require('bcrypt');
const userModel = require('../models/user');
const { validationResult } = require('express-validator'); 

exports.registerUser = (req, res) => {
  // 1. Validate request

  // 2. If VALID, find if email exists in users
  //      NEW USER (no results retrieved)
  //        a. Hash password
  //        b. Create user
  //        c. Redirect to login page
  //      EXISTING USER (match retrieved)
  //        a. Redirect user to login page with error message.

  // 3. If INVALID, redirect to register page with errors
 
  const error = validationResult(req);
  
  if(error.isEmpty()){
    const{name, email, password} = req.body;
    
    userModel.getOne({email: email}, (err, result) => {
      if(result){
        console.log(result);
        req.flash('error_msg', 'User already exists. Please login.');
        res.redirect('/login');
      } else{
        const saltRounds = 10;
        bcrypt.hash(password, saltRounds, (err,hashed) =>{
          const newUser = {
            name, 
            email : email,
            password: hashed
          };
          
          userModel.create(newUser, (err,user) => {
            if(err){
              req.flash('error_msg', 'Could not create user. Please try again.');
              res.redirect('/register');
            }else{
              console.log(user);
              req.flash('success_msg', 'You are now registered! Login below.');
              res.redirect('/login');
            }
          });
        });
      }
    });
  } else{
    const messages = error.array().map((item) => item.msg);
    req.flash('error_msg', messages.join(' '));
    res.redirect('/register');
  }
};

exports.loginUser = (req, res) => {
  // 1. Validate request

  // 2. If VALID, find if email exists in users
  //      EXISTING USER (match retrieved)
  //        a. Check if password matches hashed password in database
  //        b. If MATCH, save info to session and redirect to home
  //        c. If NOT equal, redirect to login page with error
  //      UNREGISTERED USER (no results retrieved)
  //        a. Redirect to login page with error message

  // 3. If INVALID, redirect to login page with errors
  const errors = validationResult(req);

  if(errors.isEmpty()){
    const{
      email,
      password
    } = req.body;

    userModel.getOne({email: email}, (err, user) =>{
      if(err){
        req.flash('error_msg', 'Something happened! Please try again.');
        res.redirect('/login');
      }else{
        if(user){
          //user is found
          bcrypt.compare(password, user.password, (err, result) =>{
            if(result){
              req.session.user = user._id;
              req.session.name = user.name;

              console.log(req.session);
              res.redirect('/');
            }else{
              req.flash('error_msg','Incorrect password. Please try again.');
              res.redirect('/login');
            }
          });
        }else{
          req.flash('error_msg','No registered user with that email. Please register.');
          res.redirect('/register');
        }
      }
    });
  }else{
    const messages = errors.array().map((item) => item.msg);
    req.flash('error_msg', messages.join(' '));
    res.redirect('/login');
  }
};

exports.logoutUser = (req, res) => {
  if(req.session){
    req.session.destroy(() =>{
      res.clearCookie('connect.sid')
      res.redirect('/login');
    })
  }
};
