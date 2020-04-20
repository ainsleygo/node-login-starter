const { body } = require('express-validator');

const registerValidation = [
    //name should not be empty
    body('name').not().isEmpty().withMessage("Name is required."),
    //email should not be empty and must be a valid email
    body('email').not().isEmpty().withMessage("Email is required.")
        .isEmail().withMessage("Please provide a valid email"),
    //password needs to be min 6 chars
    body('password').isLength({min : 6}).withMessage("Password must be at least 6 characters long."),
    //confirm password needs to be min 6 chars AND must match the req.body.password field
    body('confirmPass').isLength({min : 6}).withMessage("Password must be at least 6 characters long.")
    .custom((value, {req}) =>{
        if(value !== req.body.password){
            throw new Error ("Passwords must match.");
        }
        return true;
    })
];

const loginValidation = [
    //email should not be empty and must be a valid email
    body('email').not().isEmpty().withMessage('Email is required')
    .isEmail().withMessage('Please provide a valid email'),

    //password should not be empty and needs to be at least 6 chars
    body('password').not().isEmpty().withMessage('Password is required.')
];

module.exports = {registerValidation, loginValidation};
    