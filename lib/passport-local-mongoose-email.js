var util = require('util'),
    crypto = require('crypto'),
    LocalStrategy = require('passport-local').Strategy,
    BadRequestError = require('./badrequesterror');

module.exports = function(schema, options) {
    options = options || {};
    options.saltlen = options.saltlen || 32;
    options.iterations = options.iterations || 25000;
    options.keylen = options.keylen || 512;
    options.digest = options.digest || 'SHA1';
    options.encoding = options.encoding || 'hex';

    // Populate field names with defaults if not set
    options.usernameField = options.usernameField || 'email';  // Changed from username to email
    options.platformField = options.platformField || 'platform'; // Added platform field
    options.hashField = options.hashField || 'hash';
    options.saltField = options.saltField || 'salt';
    options.authToken = options.authToken || 'authToken';
    options.isAuthenticated = options.isAuthenticated || 'isAuthenticated';

    // option to convert email to lowercase when finding
    options.emailLowerCase = options.emailLowerCase || true;  // Changed from usernameLowerCase

    options.incorrectPasswordError = options.incorrectPasswordError || 'Incorrect password';
    options.incorrectEmailError = options.incorrectEmailError || 'Incorrect email';  // Changed from username
    options.missingEmailError = options.missingEmailError || 'Field %s is not set';  // Changed from username
    options.missingPlatformError = options.missingPlatformError || 'Platform is not set';  // Added platform error
    options.missingPasswordError = options.missingPasswordError || 'Password argument not set!';
    options.userEmailUnverifiedError = options.userEmailUnverifiedError || 'User did not verify email!';
    options.userExistsError = options.userExistsError || 'User already exists with email %s on platform %s';  // Modified to include platform
    options.noSaltValueStoredError = options.noSaltValueStoredError || 'Authentication not possible. No salt value stored in mongodb collection!';
    options.authTokenNotFoundError = options.authTokenNotFoundError || 'Authentication token is not found!';

    var schemaFields = {};
    if (!schema.path(options.usernameField)) {
        schemaFields[options.usernameField] = String;
    }
    if (!schema.path(options.platformField)) {
        schemaFields[options.platformField] = String;  // Added platform field
    }
    schemaFields[options.hashField] = String;
    schemaFields[options.saltField] = String;
    schemaFields[options.authToken] = String;
    schemaFields[options.isAuthenticated] = Boolean;

    // Add compound index for email and platform
    schema.index({ 
        [options.usernameField]: 1, 
        [options.platformField]: 1 
    }, { 
        unique: true 
    });

    schema.add(schemaFields);

    schema.pre('save', function(next) {
        // if specified, convert the email to lowercase
        if (options.emailLowerCase) {
            this[options.usernameField] = this[options.usernameField].toLowerCase();
        }

        next();
    });

    // Rest of the methods remain largely the same, but modified to handle email and platform
    schema.statics.authenticate = function() {
        var self = this;

        return function(email, password, platform, cb) {
            self.findByEmailAndPlatform(email, platform, function(err, user) {
                if (err) { return cb(err); }

                if (user) {
                    if(user.isAuthenticated) {
                        return user.authenticate(password, cb);
                    } else {
                        return cb(null, false, { message: options.userEmailUnverifiedError });
                    }
                } else {
                    return cb(null, false, { message: options.incorrectEmailError });
                }
            });
        }
    };

    // Modified to find by both email and platform
    schema.statics.findByEmailAndPlatform = function(email, platform, cb) {
        var queryParameters = {};
        
        if (email !== undefined && options.emailLowerCase) {
            email = email.toLowerCase();
        }
        
        queryParameters[options.usernameField] = email;
        queryParameters[options.platformField] = platform;
        
        var query = this.findOne(queryParameters);
        if (options.selectFields) {
            query.select(options.selectFields);
        }

        if (options.populateFields) {
            query.populate(options.populateFields);
        }

        if (cb) {
            query.exec(cb);
        } else {
            return query;
        }
    };

    schema.statics.register = function(user, password, cb) {
        if (!(user instanceof this)) {
            user = new this(user);
        }

        if (!user.get(options.usernameField)) {
            return cb(new BadRequestError(util.format(options.missingEmailError, options.usernameField)));
        }

        if (!user.get(options.platformField)) {
            return cb(new BadRequestError(options.missingPlatformError));
        }

        var self = this;
        self.findByEmailAndPlatform(
            user.get(options.usernameField), 
            user.get(options.platformField), 
            function(err, existingUser) {
                if (err) { return cb(err); }
                
                if (existingUser) {
                    return cb(new BadRequestError(util.format(
                        options.userExistsError, 
                        user.get(options.usernameField),
                        user.get(options.platformField)
                    )));
                }
                
                user.setPassword(password, function(err, user) {
                    if (err) {
                        return cb(err);
                    }

                    user.setAuthToken(function(err, user) {
                        if (err) {
                            return cb(err);
                        }
                      
                        user.isAuthenticated = false;
                        user.save(function(err) {
                            if (err) {
                                return cb(err);
                            }

                            cb(null, user);
                        });
                    });
                });
            }
        );
    };

    // Other methods remain the same
    schema.methods.setPassword = function (password, cb) {
        if (!password) {
            return cb(new BadRequestError(options.missingPasswordError));
        }
        
        var self = this;

        crypto.randomBytes(options.saltlen, function(err, buf) {
            if (err) {
                return cb(err);
            }

            var salt = buf.toString(options.encoding);

            crypto.pbkdf2(password, salt, options.iterations, options.keylen, options.digest, function(err, hashRaw) {
                if (err) {
                    return cb(err);
                }

                self.set(options.hashField, new Buffer(hashRaw, 'binary').toString(options.encoding));
                self.set(options.saltField, salt);

                cb(null, self);
            });
        });
    };

    schema.methods.setAuthToken = function (cb) {        
        var self = this;

        crypto.randomBytes(48, function(err, buf) {
            if (err) {
                return cb(err);
            }

            var authToken = buf.toString('hex');
            self.set(options.authToken, authToken);
            
            cb(null, self);
        });
    };

	schema.methods.authenticate = function(password, cb) {
		var self = this;
	
		if (!this.get(options.saltField)) {
		  return cb(null, false, { message: options.noSaltValueStoredError });
		}
	
		crypto.pbkdf2(password, this.get(options.saltField), options.iterations, options.keylen, options.digest, function(err, hashRaw) {
		  if (err) {
			return cb(err);
		  }
		  
		  var hash = new Buffer.from(hashRaw, 'binary').toString(options.encoding);
	
		  if (hash === self.get(options.hashField)) {
			return cb(null, self);
		  } else {
			return cb(null, false, { message: options.incorrectPasswordError });
		  }
		});
	  };

    schema.statics.createStrategy = function() {
        return new LocalStrategy(options, this.authenticate());
    };
};