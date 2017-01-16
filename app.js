var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');

//cfenv provides access to your Cloud Foundry env
var cfenv = require('cfenv');
//get the app env from Cloud Foundry
var appEnv = cfenv.getAppEnv();

//Add for SSO
var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;


var routes = require('./routes/index');
var events = require('./routes/events');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({resave: 'true', saveUninitialized: 'true', secret: 'keyboard cat'}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

app.use('/', routes);
app.use('/events', events);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});

// find config object for the SSO services from VCAP_SERVICES through cfenv/appEnv
var ssoConfig = appEnv.getService(/Single Sign On.*/)
var client_id = ssoConfig.credentials.clientId;
var client_secret = ssoConfig.credentials.secret;
var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
var token_url = ssoConfig.credentials.tokenEndpointUrl;
var issuer_id = ssoConfig.credentials.issuerIdentifier;
// you MUST change the host route to match your application name
var callback_url = 'https://bluemix-ambassador.mybluemix.net/auth/sso/callback';

var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;
var Strategy = new OpenIDConnectStrategy({
                 authorizationURL : authorization_url,
                 tokenURL : token_url,
                 clientID : client_id,
                 scope: 'openid',
                 response_type: 'code',
                 clientSecret : client_secret,
                 callbackURL : callback_url,
                 skipUserProfile: true,
                 issuer: issuer_id},
  function(accessToken, refreshToken, profile, done) {
            process.nextTick(function() {
    profile.accessToken = accessToken;
    profile.refreshToken = refreshToken;
    done(null, profile);
          })
});
passport.use(Strategy);
app.get('/login', passport.authenticate('openidconnect', {}));

function ensureAuthenticated(req, res, next) {
  if(!req.isAuthenticated()) {
              req.session.originalUrl = req.originalUrl;
    res.redirect('/login');
  } else {
    return next();
  }
}

app.get('/auth/sso/callback',function(req,res,next) {
      var redirect_url = req.session.originalUrl;
            passport.authenticate('openidconnect',{
                 successRedirect: redirect_url,
                 failureRedirect: '/failure',
          })(req,res,next);
        });


app.get('/hello', ensureAuthenticated, function(req, res) {
             res.send('Hello, '+ req.user['id'] + '!'); });

app.get('/failure', function(req, res) {
             res.send('login failed'); });

app.get(‘logout’, function(req, res) {
          req.logout();
          res.redirect('https://sso-sssaini.mybluemix.net/idaas/mtfim/sps/idaas/logout');
      });
module.exports = app;
