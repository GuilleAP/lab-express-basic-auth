const { Router } = require('express');
const router = new Router();

const bcryptjs = require('bcryptjs');
const saltRounds = 10;

const User = require('../models/User.model');
 
// GET route ==> to display the signup form to users
router.get('/signup', (req, res, next) => {
    res.render('auth/signup');
})

router.get('/userProfile', (req, res, next) => {
  res.render('users/user-profile');
})

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
 
  const { username, password } = req.body;

  bcryptjs
    .genSalt(saltRounds)
    .then(salt => bcryptjs.hash(password, salt))
    .then(hashedPassword => {
      return User.create({
        username,
        password: hashedPassword
      });
    })
    .then(userFromDB => {
      console.log('Newly created user is: ', userFromDB);
    })
    .then(userFromDB => {
      res.redirect('/userProfile');
    })
    .catch(error => next(error));
});
 
module.exports = router;