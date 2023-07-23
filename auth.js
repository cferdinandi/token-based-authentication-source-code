/*

	This file can be used with Cloudflare Workers to create
	your own dummy API for token-based authentication.

	Call the API from a browser using the fetch() method.
	Change the endpoint to point to your serverless function.

	fetch('https://auth-guide.gomakethings.workers.dev?type={type}');

	Allowed Types:

	- password: get a token with the password flow
	- implicit: get a token with the the implicit flow
	- auth-code: get an auth code with the auth code flow
	- token: get a token from an auth code
	- refresh: refresh an expired auth token with a refresh token
	- wizards: get a list of wizards with a valid token
	- expire: expire a token

*/

// Define response headers
let headers = new Headers({
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
	'Access-Control-Allow-Headers': '*'
});

/**
 * Generate a token
 * @return {Number} The token
 */
function getToken () {
	return parseInt(new Date().getTime() / 1000, 10);
}

/**
 * Get the bearer token from a request
 * @param  {Request} request The request object
 * @return {String}          The bearer token
 */
function getBearer (request) {
	let auth = request.headers.get('Authorization');
	return auth ? auth.replace('Bearer ', '') : null;
}

/**
 * Get the basic auth credentials from a request
 * @param  {Request} request The request object
 * @return {Object}          The username and password
 */
function getBasicAuth (request) {
	let auth = request.headers.get('Authorization');
	if (!auth) return null;
	let [username, password] = atob(auth.replace('Basic ', '')).split(':');
	return {username, password};
}

/**
 * Handle expiring a token
 * @param  {Request}  request The request object
 * @return {Response}         The response object
 */
async function handleExpire (request) {

	// Get the token
	let token = getBearer(request);

	// Check that there's a token
	if (!token) {
		return new Response('no token provided', {
			status: 401,
			headers: headers
		});
	}

	// return a Response object
	return new Response('Expired', {
		status: 200,
		headers: headers
	});

}

/**
 * Handle password auth type
 * @param  {Request}  request The request object
 * @param  {Object}   params  The request search parameters
 * @return {Response}         The response object
 */
async function handlePassword (request, params) {

	// Get the credentials
	let {username, password} = getBasicAuth(request);

	// Check the username and password
	if (username !== 'merlin@wizardschool.org' || password !== 'spellbook123') {
		return new Response('invalid username and password', {
			status: 401,
			headers: headers
		});
	}

	// Create the response object
	let resp = {
		token: getToken(),
		expiresIn: 60 * 60 * 24 * 14
	};
	if (params.get('refresh')) {
		resp.refresh = REFRESH_TOKEN;
	}

	// return a Response object
	return new Response(JSON.stringify(resp), {
		status: 200,
		headers: headers
	});

}

/**
 * Handle auth code token
 * @param  {Request}  request The request object
 * @param  {Object}   params  The request search parameters
 * @return {Response}         The response object
 */
async function handleToken (request, params) {

	// Get the request body
	let body = await request.json();

	// Get a token
	let token = getToken();

	// Check if client ID and secret are valid
	if ((body.client_id !== 'this!$dangerous' || body.client_secret !== 'do_not_put_credentials_in_javascript') && !body.code_verifier) {
		return new Response('invalid client ID and secret', {
			status: 401,
			headers: headers
		});
	}

	// Check if auth code is valid and less than 10 minutes old
	let isValid = false;
	if (body.code && body.code.startsWith('0aUtH_')) {
		let code = parseFloat(body.code.replace('0aUtH_', ''));
		if (token - code < (60 * 10)) {
			isValid = true;
		}
	}

	// Check if auth code is valid
	if (!isValid) {
		return new Response('invalid authentication code', {
			status: 401,
			statuText: 'invalid authentication code',
			headers: headers
		});
	}

	// Create the response object
	let resp = {
		token,
		expiresIn: 60 * 60 * 24 * 14
	};
	if (params.get('refresh')) {
		resp.refresh = REFRESH_TOKEN;
	}

	// return a Response object
	return new Response(JSON.stringify(resp), {
		status: 200,
		headers: headers
	});

}

/**
 * Handle refresh tokens
 * @param  {Request}  request The request object
 * @return {Response}         The response object
 */
async function handleRefresh (request) {

	// Get the refresh token
	let refresh = getBearer(request);

	// Check the username and password
	if (refresh !== REFRESH_TOKEN) {
		return new Response('invalid refresh token', {
			status: 401,
			headers: headers
		});
	}

	// return a Response object
	return new Response(JSON.stringify({
		token: getToken(),
		refresh: REFRESH_TOKEN,
		expiresIn: 60 * 60 * 24 * 14
	}), {
		status: 200,
		headers: headers
	});

}

/**
 * Handle wizard data
 * @param  {Request}  request The request object
 * @param  {Object}   params  The request search parameters
 * @return {Response}         The response object
 */
async function handleWizards (request, params) {

	// Get the authtoken
	let token = getBearer(request);

	// Check if token is valid
	let now = getToken();
	let isValid = now - token < (params.get('long-session') ? 60 * 60 : 15);

	// Check if auth code is valid
	if (!isValid) {
		return new Response('expired token', {
			status: 401,
			headers: headers
		});
	}

	// return a Response object
	return new Response(JSON.stringify(['Merlin', 'Gandalf', 'Radagast']), {
		status: 200,
		headers: headers
	});

}

/**
 * Handle implicit auth type
 * @param  {Request}  request The request object
 * @param  {Object}   params  The request search parameters
 * @param  {Boolean}  isCode  If true, return authentication code
 * @return {Response}         The response object
 */
async function handleHTML (request, params, isCode) {

	// The redirect URL
	let redirect = params.get('redirect');

	// Message HTML
	let message = `<p>No redirect URL provided.</p>`;
	if (redirect) {

		// Add the token to the redirect URL
		let url = new URL(redirect);
		url.searchParams.set((isCode ? 'code' : 'token'), (isCode ? `0aUtH_${getToken()}` : getToken()));

		// If there's an anti-forgery token, add it
		if (isCode) {
			let state =  params.get('state');
			if (state) {
				url.searchParams.set('state', state);
			}
		}

		// Create the message
		message =
			`<p>This app wants to access your...</p>
			<ul>
				<li>Username</li>
				<li>Email Address</li>
			</ul>

			<p><a class="btn" href="${url.toString()}">Allow Access</a></p>`;

	}

	// Create page HTML
	let html =
		`<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="utf-8">
			<title>Sign In with WizardSchool</title>
			<meta name="viewport" content="width=device-width, initial-scale=1.0">

			<style type="text/css">
				body {
					margin: 0 auto;
					max-width: 40em;
					width: 88%;
				}

				.btn {
					background-color: #e5e5e5;
					border: 1px solid #808080;
					border-radius: 0.25em;
					color: #272727;
					padding: 0.25em 0.5em;
					text-decoration: none;
				}

				.btn:hover {
					background-color: #0088cc;
					border-color: #00527a;
					color: #ffffff;
				}
			</style>
		</head>
		<body>
			<h1>Sign In with Wizard School</h1>
			${message}
		</body>
		</html>`;

	return new Response(html, {
		headers: {
			'content-type': 'text/html;charset=UTF-8',
		}
	});

}

/**
 * Respond to the request
 * @param {Request} request
 */
async function handleRequest (request) {

	// Handle the OPTIONS method
	if (request.method === 'OPTIONS') {
		return new Response(null, {
			status: 200,
			headers: headers
		});
	}

	// Get the request body
	let params = new URL(request.url).searchParams;
	let authType = params.get('type');

	if (authType === 'password') {
		return await handlePassword(request, params);
	}

	if (authType === 'implicit' && request.method === 'GET') {
		return await handleHTML(request, params);
	}

	if (authType === 'auth-code') {
		return await handleHTML(request, params, true);
	}

	if (authType === 'token') {
		return await handleToken(request, params);
	}

	if (authType === 'refresh') {
		return await handleRefresh(request);
	}

	if (authType === 'wizards') {
		return await handleWizards(request, params);
	}

	if (authType === 'expire') {
		return await handleExpire(request);
	}

	// Catchall response
	return new Response('Invalid HTTP method', {
		status: 405,
		headers: headers
	});

}

// Listen for API calls
addEventListener('fetch', function (event) {
	event.respondWith(handleRequest(event.request));
});
