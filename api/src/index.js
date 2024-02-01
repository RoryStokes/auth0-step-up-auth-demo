const functions = require("@azure/functions");
/**
 * jwks-rsa and jsonwebtoken have been selected as these are open source libraries published by Auth0
 */
const jwksClient = require("jwks-rsa");
const jwt = require("jsonwebtoken");

const auth0Domain = "bd-450.au.auth0.com";

const client = jwksClient({
  jwksUri: `https://${auth0Domain}/.well-known/jwks.json`,
});

/**
 * Borrowed from example on jsonwebtoken readme
 * https://github.com/auth0/node-jsonwebtoken?tab=readme-ov-file#jwtverifytoken-secretorpublickey-options-callback
 */
const getKey = (header, callback) => {
  client.getSigningKey(header.kid, function (err, key) {
    callback(err, key?.publicKey || key?.rsaPublicKey);
  });
};

const unauthorisedResponse = {
  status: 401,
  body: "Unauthorised",
};

const forbiddenResponse = {
  status: 403,
  body: "Forbidden",
};

/**
 * Wraps an Azure handler function with JWT bearer token validation
 * @param {{requiredScopes?: string[]}} opts
 * @param {(request: functions.HttpRequest, context: functions.InvocationContext, token: import("jsonwebtoken").Jwt) => FunctionResult<functions.HttpResponseInit | functions.HttpResponse>} handler
 * @returns {functions.HttpHandler}
 */
const authorisedHandler = (opts, handler) => async (request, context) => {
  const authorisationHeader = request.headers.get("authorization");
  if (authorisationHeader === null) return unauthorisedResponse;
  const [bearer, tokenString] = authorisationHeader.split(" ");
  if (bearer !== "Bearer" || tokenString === undefined)
    return unauthorisedResponse;
  return new Promise((resolve, reject) =>
    jwt.verify(tokenString, getKey, { complete: true }, (error, decoded) =>
      decoded !== undefined ? resolve(decoded) : reject(error)
    )
  ).then(
    (token) => {
      const scopes = token.payload.scope?.split(" ") || [];
      if (
        opts.requiredScopes === undefined ||
        opts.requiredScopes.every((s) => scopes.includes(s))
      ) {
        return handler(request, context, token);
      } else {
        return forbiddenResponse;
      }
    },
    (_) => ({ status: 401, body: "Invalid token" })
  );
};

functions.app.http("test-endpoint", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  handler: authorisedHandler({}, async (request, context, token) => {
    context.log(`Http function processed request for url "${request.url}"`);

    return { jsonBody: { escalated: false, scopes: token.payload.scope } };
  }),
});

functions.app.http("escalated-endpoint", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  handler: authorisedHandler(
    { requiredScopes: ["manage:secrets"] },
    async (request, context, token) => {
      context.log(`Http function processed request for url "${request.url}"`);

      return { jsonBody: { escalated: true, scopes: token.payload.scope } };
    }
  ),
});
