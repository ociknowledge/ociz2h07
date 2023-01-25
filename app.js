/*
* File containing all the routes for the Sample Application.
* @Copyright Oracle
*/

//Import libraries
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var exphbs = require('express-handlebars');
var expressValidator = require('express-validator');
var session = require('express-session');
var passport = require('passport');
var OIDCStrategy = require('passport-idcs').OIDCStrategy;
var IdcsAuthenticationManager = require('passport-idcs').IdcsAuthenticationManager;
var http = require('http');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
//Loading the configurations
var auth = require('./auth.js');
var config = require('./config.js');
const { escape } = require('querystring');

//Init app for express framework.
var app = express();

// View Engine setting
app.set('views', path.join(__dirname, 'views'));
app.engine('handlebars', exphbs({
  defaultLayout: 'publicLayout',
  helpers: {
    toString: function (object) {
      return JSON.stringify(object, null, 2);
    },
    ifequals: function (obj1, obj2, options) {
      if (obj1 == obj2) {
        return options.fn(this);
      } else {
        return options.inverse(this);
      }
    }
  }
}));

app.set('view engine', 'handlebars');

//BodyParser middleware setting
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

//Public folder for static content.
app.use(express.static(path.join(__dirname, 'public')));

//Express Session setting
app.use(session({
  secret: 'sample_application',
  saveUninitialized: true,
  resave: true
}));

// serialize and deserialize
passport.serializeUser(function (user, done) {
  done(null, user);
});
passport.deserializeUser(function (obj, done) {
  done(null, obj);
});

passport.use(new OIDCStrategy(auth.oracle,
  (idToken, tenant, user, done) => {
    done(null, user);
  }));


//Express Validator setting
app.use(expressValidator({
  errorFormatter: function (param, msg, value) {
    var namespace = param.split('.')
      , root = namespace.shift()
      , formParam = root;

    while (namespace.length) {
      formParam += '[' + namespace.shift() + ']';
    }
    return {
      param: formParam,
      msg: msg,
      value: value
    };
  }
}));

//Global variables
app.use(function (req, res, next) {
  res.locals.user = req.user || null;
  next();
});

//Passport initialization
app.use(passport.initialize());
app.use(passport.session());

//-------------
//Routes section
//Public acess
app.get('/', function (req, res) {
  res.render('index', { title: 'Index', layout: 'zeroToHeroPublic', });
});

//Route for /logout.
//The Node.js express framework defines a mechanism to log the user out of the web application.
//The handler of the /logout route uses the res.clearCookie() express function to clear all of the cookies that have been set,
//and then redirects the browser to Oracle Identity Cloud Service's log out URL sending parameters to redirect the user browser
//back to the sample application after logging  out from Oracle Identity Cloud Service.
app.get('/logout', function (req, res) {
  var id_token = req.session.id_token;
  var logouturl = auth.oracle.AudienceServiceUrl + auth.oracle.logoutSufix + '?post_logout_redirect_uri=http%3A//localhost%3A3000&id_token_hint=' + id_token;
  req.session.destroy(function (err) {
    if (err) {
      console.log(err);
    } else {
      req.logout();
      res.clearCookie();
      res.redirect(logouturl);
    }
  })
});

//Route for /oauth/oracle
//The handler of the /auth/oracle route uses the IdcsAuthenticationManager.getAuthorizationCodeUrl() SDK's function to generate the authorization URL.
app.get("/auth/oracle", function (req, res) {
  //Authentication Manager loaded with the configurations.
  am = new IdcsAuthenticationManager(auth.oracle);
  //Using Authentication Manager to generate the Authorization Code URL, passing the
  //application's callback URL as parameter, along with code value and code parameter.
  //The IdcsAuthenticationManager.getAuthorizationCodeUrl() SDK's function uses promise to redirect the request upon successful
  //generation of the authorization code URL, or to render an error instead
  am.getAuthorizationCodeUrl(auth.oracle.redirectURL, auth.oracle.scope, "1234", "code")
    .then(function (authZurl) {
      //Redirecting the browser to the Oracle Identity Cloud Service Authorization URL.
      res.redirect(authZurl);
    }).catch(function (err) {
      res.end(err);
    })
});

//Route for /callback
//The sample application handles the /callback route, and uses the authorization code, sent as a query parameter,
//to request an access token. The access token is stored as a cookie, and then sent to the browser for future use.
app.get("/callback", function (req, res) {
  //Authentication Manager loaded with the configurations.
  var am = new IdcsAuthenticationManager(auth.oracle);
  //Getting the authorization code from the "code" parameter
  var authZcode = req.query.code;
  //Using the Authentication Manager to exchange the Authorization Code to an Access Token.
  //The IdcsAuthenticationManager.authorizationCode() SDK's function uses promise (then/catch statement) to set
  //the access token as a cookie, and to redirect the browser to the /auth.html page.
  am.authorizationCode(authZcode)
    .then(function (result) {
      //Getting the Access Token Value.
      req.session.access_token = result.access_token;
      req.session.id_token = result.id_token;
      res.cookie(config.IDCS_COOKIE_NAME, result.access_token);
      res.header('idcs_user_assertion', result.access_token)
      res.redirect('/auth.html');
    }).catch(function (err) {
      res.end(err);
    })
});


//Uses passport to create a User Session in Node.js.
//Passport sets a user attribute in the request as a json object.
//The /auth route's handler calls the passport.authenticate() function, with Oracle Identity Cloud Service's strategy
//name as a parameter to set up the user session, and then redirects the browser to the /home URL.
app.get('/auth', passport.authenticate(config.IDCS_STRATEGY_NAME, {}), function (req, res) {
  res.redirect('/home');
});

//The /home URL is a protected resource.
//The sample web application uses the ensureAuthenticated function to handle these protected resources.
//Protected route. Uses ensureAuthenticated function.
app.get('/home', ensureAuthenticated, function (req, res) {
  res.render('home', {
    layout: 'zeroToHeroPrivate',
    title: 'Home',
    user: req.user,
  });
});

// Set Port
app.set('port', (process.env.PORT || config.APP_DEFAULT_PORT));
app.listen(app.get('port'), function () {
  console.log('Server started on port ' + app.get('port'));
});

//Function to help verify if the user is authenticated in Passwport.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}
module.exports = app;
