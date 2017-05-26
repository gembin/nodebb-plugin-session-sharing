"use strict";

/* globals process, require, module */

var meta = module.parent.require('./meta');
var user = module.parent.require('./user');
var groups = module.parent.require('./groups');

var SocketPlugins = require.main.require('./src/socket.io/plugins');

var _ = module.parent.require('underscore');
var winston = module.parent.require('winston');
var async = require('async');
var db = module.parent.require('./database');
var nconf = module.parent.require('nconf');

var fs = require('fs');
var jwt = require('jsonwebtoken');

var controllers = require('./lib/controllers');
var nbbAuthController = module.parent.require('./controllers/authentication');

var plugin = {
	ready: false,
	settings: {
		name: 'appId',
		cookieName: 'token',
		cookieDomain: undefined,
		secret: '',
		behaviour: 'trust',
		noRegistration: 'off',
		'payload:id': 'id',
		'payload:email': 'email',
		'payload:username': 'username',
		'payload:nickName': 'nickName',
		'payload:firstName': 'firstName',
		'payload:lastName': 'lastName',
		'payload:picture': 'picture',
		'payload:role': 'role',
		'payload:adminRole': 'admin',
		'payload:parent': undefined
	}
};

plugin.init = function (params, callback) {
	var router = params.router,
		hostMiddleware = params.middleware;

	router.get('/admin/plugins/session-sharing', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
	router.get('/api/admin/plugins/session-sharing', controllers.renderAdminPage);

	router.get('/api/session-sharing/lookup', controllers.retrieveUser);

	if (process.env.NODE_ENV === 'development') {
		router.get('/debug/session', plugin.generate);
	}

	plugin.reloadSettings(callback);
};

plugin.appendConfig = function (config, callback) {
	config.sessionSharing = {
		logoutRedirect: plugin.settings.logoutRedirect,
		loginOverride: plugin.settings.loginOverride
		//loginOverride: false
	};

	callback(null, config);
};

/* Websocket Listeners */

SocketPlugins.sessionSharing = {};

SocketPlugins.sessionSharing.showUserIds = function (socket, data, callback) {
	// Retrieve the hash and find matches
	var uids = data.uids;
	var payload = [];
	var match, idx;

	payload.length = uids.length;

	if (uids.length) {
		db.getObject(plugin.settings.name + ':uid', function (err, hash) {
			for (var remoteId in hash) {
				idx = uids.indexOf(hash[remoteId]);
				if (hash.hasOwnProperty(remoteId) && idx !== -1) {
					payload[idx] = remoteId;
				}
			}

			callback(null, payload);
		});
	} else {
		callback(new Error('no-uids-supplied'));
	}
};

SocketPlugins.sessionSharing.findUserByRemoteId = function (socket, data, callback) {
	if (data.remoteId) {
		plugin.getUser(data.remoteId, callback);
	} else {
		callback(new Error('no-remote-id-supplied'));
	}
};

/* End Websocket Listeners */

/*
 *	Given a remoteId, show user data
 */
plugin.getUser = function (remoteId, callback) {
	async.waterfall([
		async.apply(db.getObjectField, plugin.settings.name + ':uid', remoteId),
		function (uid, next) {
			if (uid) {
				user.getUserFields(uid, ['username', 'userslug', 'picture'], next);
			} else {
				setImmediate(next);
			}
		}
	], callback);
};

plugin.base64toPem = function (base64) {
	for (var result = "", lines = 0; result.length - lines < base64.length; lines++) {
		result += base64.substr(result.length - lines, 64) + "\n"
	}
	return "-----BEGIN PUBLIC KEY-----\n" + result + "-----END PUBLIC KEY-----";
};

plugin.process = function (token, callback) {
	// token format:
	// "jwt-token-xxxxx;Version=1;Domain=xxx.com;Path=/;Max-Age=86400;HttpOnly"
	// winston.info('payload token:', token)
	var jwtToken = token.toString().split(";")[0];
	token = jwtToken.substring(1);
	// winston.info('token: ', token)
	var decoded = jwt.verify(token, plugin.base64toPem(plugin.settings.secret));
	//var decoded = jwt.decode(t, {complete: true});
	winston.info('[session-sharing] decoded token: ', decoded);

	async.waterfall([
		async.apply(jwt.verify, token, plugin.base64toPem(plugin.settings.secret)),
		async.apply(plugin.verifyToken),
		async.apply(plugin.findUser),
		async.apply(plugin.verifyUser)
	], callback);
};


plugin.extractUserProfile = function (payload) {
	var parent = plugin.settings['payload:parent'],
		id = parent ? payload[parent][plugin.settings['payload:id']] : payload[plugin.settings['payload:id']],
		email = parent ? payload[parent][plugin.settings['payload:email']] : payload[plugin.settings['payload:email']],
		username = parent ? payload[parent][plugin.settings['payload:username']] : payload[plugin.settings['payload:username']],
		firstName = parent ? payload[parent][plugin.settings['payload:firstName']] : payload[plugin.settings['payload:firstName']],
		lastName = parent ? payload[parent][plugin.settings['payload:lastName']] : payload[plugin.settings['payload:lastName']],
		picture = parent ? payload[parent][plugin.settings['payload:picture']] : payload[plugin.settings['payload:picture']],
		nickName = parent ? payload[parent][plugin.settings['payload:nickName']] : payload[plugin.settings['payload:nickName']],
		roles = parent ? payload[parent][plugin.settings['payload:roles']] : payload[plugin.settings['payload:roles']];

	// var fullname = [firstName, lastName].join(' ').trim();
	var fullname = nickName;
	if (!username) {
		username = nickName;
	}

	var profile = {};
	profile.id = id;
	profile.username = username;
	profile.email = email;
	profile.fullname = fullname;
	profile.picture = picture;
	profile.roles = roles || [];  //it's []
	return profile;
}

plugin.verifyToken = function (payload, callback) {
	var profile = plugin.extractUserProfile(payload);
	winston.info('[session-sharing] user profile: ', profile);
	if (!profile.id || !profile.username) {
		return callback(new Error('payload-invalid'));
	}
	callback(null, profile);
};


plugin.findUser = function (profile, callback) {
	// If payload id resolves to a user, return the uid, otherwise register a new user
	winston.verbose('[session-sharing] Payload verified');

	user.getUidByUsername(profile.username, function (err, uid) {
		winston.verbose('err:', err, 'uid: ', uid)
		if (err) { return callback(err); }
		if (uid) {
			if (plugin.settings.updateProfile === 'on') {
				plugin.updateUserProfile(uid, profile, callback);
			}
		} else {
			// No match, create a new user
			plugin.createUser(profile, callback);
		}
	});
};

plugin.verifyUser = function (uid, callback) {
	// Check ban state of user, reject if banned
	user.isBanned(uid, function (err, banned) {
		callback(err || banned ? new Error('banned') : null, uid);
	});
};

plugin.updateUserProfile = function (uid, profile, callback) {
	async.waterfall([
		function (next) {
			user.getUserFields(uid, ['username', 'email', 'fullname'], next);
		},
		function (existingFields, next) {
			var obj = {};
			winston.verbose('[session-sharing] existingFields:', existingFields)
			// username cannot be updated from AIR
			//if (existingFields.username !== username) {
			//	obj.username = username;
			//}

			if (existingFields.email !== profile.email) {
				obj.email = profile.email;
			}

			if (existingFields.fullname !== profile.fullname) {
				obj.fullname = profile.fullname;
			}

			if (Object.keys(obj).length) {
				obj.uid = uid;
				user.updateProfile(uid, obj, function (err, userObj) {
					if (err) {
						winston.warn('[session-sharing] Unable to update profile information for uid: ' + uid + '(' + err.message + ')');
					}
					// If it errors out, not that big of a deal, continue anyway.
					next(null, userObj || existingFields);
				});
			} else {
				setImmediate(next, null, {});
			}
		},
		function (userObj, next) {
			if (profile.picture) {
				return db.setObjectField('user:' + uid, 'picture', profile.picture, next);
			}
			next(null);
		}
	], function (err) {
		return callback(err, uid);
	});
}

plugin.createUser = function (profile, callback) {
	if (plugin.settings.noRegistration === 'on') {
		return callback(new Error('no-match'));
	}

	winston.info('[session-sharing] No user found, creating a new user for this login: ', profile);
	//username = username.trim().replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, '-');

	user.create({
		username: profile.username,
		email: profile.email,
		picture: profile.picture,
		fullname: profile.nickName
	}, function (err, uid) {
		if (err) { return callback(err); }

		var roles = profile.roles.map(function (value) {
			return value.toUpperCase();
		});
		winston.info('[session-sharing] user roles:', roles);
		var pos = roles.indexOf(String(plugin.settings['payload:roleAdmin']).trim().toUpperCase());
		if (pos != -1) {
			groups.join('administrators', uid, function (r) {
				winston.info('[session-sharing] join admin group:', uid, ', result:', r);
			});
		} else {
			winston.info('[session-sharing] normal user:', profile.username);
		}

		callback(err, uid);
	});
};

plugin.addMiddleware = function (req, res, next) {
	function handleGuest(req, res, next) {
		if (plugin.settings.guestRedirect && !req.originalUrl.startsWith(nconf.get('relative_path') + '/login?local=1')) {
			// If a guest redirect is specified, follow it
			res.redirect(plugin.settings.guestRedirect.replace('%1', encodeURIComponent(nconf.get('url') + req.originalUrl)));
		} else if (res.locals.fullRefresh === true) {
			res.redirect(req.url);
		} else {
			next();
		}
	}

	// Only respond to page loads by guests, not api or asset calls
	var hasSession = req.hasOwnProperty('user') && req.user.hasOwnProperty('uid') && parseInt(req.user.uid, 10) > 0;
	var hasLoginLock = req.session.hasOwnProperty('loginLock');

	if (
		!plugin.ready ||	// plugin not ready
		(plugin.settings.behaviour === 'trust' && hasSession) ||	// user logged in + "trust" behaviour
		(plugin.settings.behaviour === 'revalidate' && hasLoginLock) ||
		req.originalUrl.startsWith(nconf.get('relative_path') + '/api')	// api routes
	) {
		// Let requests through under "revalidate" behaviour only if they're logging in for the first time
		delete req.session.loginLock;	// remove login lock for "revalidate" logins

		return next();
	} else {
		// Hook into ip blacklist functionality in core
		if (meta.blacklist.test(req.ip)) {
			if (hasSession) {
				req.logout();
				res.locals.fullRefresh = true;
			}

			plugin.cleanup({ res: res });
			return handleGuest.apply(null, arguments);
		}

		if (Object.keys(req.cookies).length && req.cookies.hasOwnProperty(plugin.settings.cookieName) && req.cookies[plugin.settings.cookieName].length) {
			return plugin.process(req.cookies[plugin.settings.cookieName], function (err, uid) {
				if (err) {
					switch (err.message) {
						case 'banned':
							winston.info('[session-sharing] uid ' + uid + ' is banned, not logging them in');
							next();
							break;
						case 'payload-invalid':
							winston.warn('[session-sharing] The passed-in payload was invalid and could not be processed');
							next();
							break;
						case 'no-match':
							winston.info('[session-sharing] Payload valid, but local account not found.  Assuming guest.');
							handleGuest.call(null, req, res, next);
							break;
						default:
							winston.warn('[session-sharing] Error encountered while parsing token: ' + err.message);
							next();
							break;
					}

					return;
				}

				winston.info('[session-sharing] Processing login for uid ' + uid + ', path ' + req.originalUrl);
				req.uid = uid;
				nbbAuthController.doLogin(req, uid, function () {
					winston.info('[session-sharing] Logined uid:', uid);
					req.session.loginLock = true;
					res.redirect(req.originalUrl);
				});
			});
		} else if (hasSession) {
			// Has login session but no cookie, can assume "revalidate" behaviour
			user.isAdministrator(req.user.uid, function (err, isAdmin) {
				if (!isAdmin) {
					req.logout();
					res.locals.fullRefresh = true;
					handleGuest(req, res, next);
				} else {
					// Admins can bypass
					return next();
				}
			});
		} else {
			handleGuest.apply(null, arguments);
		}
	}
};

plugin.cleanup = function (data, callback) {
	if (plugin.settings.cookieDomain) {
		winston.verbose('[session-sharing] Clearing cookie');
		data.res.clearCookie(plugin.settings.cookieName, {
			domain: plugin.settings.cookieDomain,
			expires: new Date(),
			path: '/'
		});
	}

	if (typeof callback === 'function') {
		callback();
	} else {
		return true;
	}
};

plugin.generate = function (req, res) {
	var payload = {};
	payload[plugin.settings['payload:id']] = 1;
	payload[plugin.settings['payload:username']] = 'testUser';
	payload[plugin.settings['payload:email']] = 'testUser@example.org';
	payload[plugin.settings['payload:firstName']] = 'Test';
	payload[plugin.settings['payload:lastName']] = 'User';

	var token = jwt.sign(payload, plugin.settings.secret);
	res.cookie(plugin.settings.cookieName, token, {
		maxAge: 1000 * 60 * 60 * 24 * 21,
		httpOnly: true,
		domain: plugin.settings.cookieDomain
	});

	res.sendStatus(200);
};

plugin.addAdminNavigation = function (header, callback) {
	header.plugins.push({
		route: '/plugins/session-sharing',
		icon: 'fa-user-secret',
		name: 'Session Sharing'
	});

	callback(null, header);
};

plugin.reloadSettings = function (callback) {
	meta.settings.get('session-sharing', function (err, settings) {
		if (err) {
			return callback(err);
		}

		if (!settings.hasOwnProperty('secret') || !settings.secret.length) {
			winston.error('[session-sharing] JWT Secret not found, session sharing disabled.');
			return callback();
		}

		if (!settings['payload:username'] && !settings['payload:firstName'] && !settings['payload:lastName']) {
			settings['payload:username'] = 'username';
		}

		winston.info('[session-sharing] Settings OK');
		plugin.settings = _.defaults(_.pick(settings, Boolean), plugin.settings);
		plugin.ready = true;

		callback();
	});
};

module.exports = plugin;