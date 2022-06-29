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
  res.render('users/user-profile', { userInSession: req.session.currentUser });
})

// POST route ==> to process form data
router.post('/signup', (req, res, next) => {
 
  const { username, password } = req.body;

  if (!username || !password) {
    res.render('auth/signup', { errorMessage: 'All fields are mandatory. Please provide your username and password.' });
    return;
  }

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
    .catch(error => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: error.message });
      } else if (error.code === 11000) {
        res.status(500).render('auth/signup', {
           errorMessage: 'Username and email need to be unique. Either username or email is already used.'
        });
      } else {
        next(error);
      }
    });
});


///////////////////////LOGIN///////////////////////

router.get('/login', (req, res, next) => {
  res.render('auth/login');
});


router.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  console.log(username, password)
 
  if (username === '' || password === '') {
    res.render('auth/login', {
      errorMessage: 'Please enter both, username and password to login.'
    });
    return;
  }

  console.log('SESSION =====> ', req.session);
 
  User.findOne({ username })
    .then(user => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'User is not registered. Try with other user.' });
        return;
      } else if (bcryptjs.compareSync(password, user.password)) {
        //res.render('users/user-profile', { user });
        req.session.currentUser = user;
        res.redirect('/userProfile');
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password.' });
      }
    })
    .catch(error => next(error));
});


router.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    res.redirect('/');
  });
});


module.exports = router;