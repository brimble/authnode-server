const jwt = require('jwt-simple');
const config = require('../config');
const User = require('../models/user');

function tokenForUser(user){
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user._id, iat: timestamp }, config.secret);
}

exports.signin = function(req,res,next){
  // user has already had email/pass authed
  // just need to give token.
  // req.user from passport
  res.send({token: tokenForUser(req.user)});
}

exports.signup = function(req,res,next){
  const email = req.body.email;

  const password = req.body.password;
  if(!email || !password){
      return res.status(422).send({error: ' Provide both user/password'});
  }

  // See if a user with the given email exists
  User.findOne({ email: email }, function(err,existingUser){
    if(err){
      return next(err);
    }

    // If a user with email does exist return an error
    if(existingUser){
      return res.status(422).send({error: 'Email is in use.'});
    }

    // if a user with email does not exist, create and save user record
    const user = new User({email: email, password:password});
    user.save(function(err){
      if(err){
        return next(err);
      }

      // respone to request inidicating the user was created.
      res.json({token: tokenForUser(user)});
    });
  });
}
