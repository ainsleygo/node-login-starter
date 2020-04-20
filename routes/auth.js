const router = require('express').Router();
const userController = require('../controllers/userController');
const { registerValidation, loginValidation } = require('../validators.js');
const { isPublic, isPrivate } = require('../middlewares/checkAuth');

// GET login to display login page
router.get('/login',isPublic ,(req, res) => {
  res.render('login', {
    pageTitle: 'Login',
  });
});

// GET register to display registration page
router.get('/register', isPublic, (req, res) => {
  res.render('register', {
    pageTitle: 'Registration',
  });
});

// POST methods for form submissions
//register validation b4 usercontroller.register so it will validate first
router.post('/register',isPublic, registerValidation ,userController.registerUser);
router.post('/login', isPublic, loginValidation, userController.loginUser);

// logout
router.get('/logout', isPrivate, userController.logoutUser);

module.exports = router;
