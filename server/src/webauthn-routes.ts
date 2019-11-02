import * as express from 'express';
import {
  randomBase64URLBuffer,
  generateServerMakeCredRequest,
  generateServerGetAssertion,
  verifyAuthenticatorAttestationResponse,
  verifyAuthenticatorAssertionResponse
} from './webauthn';
const config = require('../config.json');
const base64url = require('base64url');
const router = express.Router();
import { database } from './database';
import { EncodedPublicKeyCredential } from './webauthn';

router.post('/register', (request, response) => {
  if (!request.body || !request.body.email || !request.body.name) {
    response.json({
      status: 'failed',
      message: 'Request missing name or email field!'
    });
    return;
  }

  const email = request.body.email;
  const name = request.body.name;

  if (database[email] && database[email].registered) {
    response.json({
      status: 'failed',
      message: `email ${email} already exists`
    });
    return;
  }

  database[email] = {
    name,
    registered: false,
    id: randomBase64URLBuffer(),
    authenticators: []
  };

  const challengeMakeCred = generateServerMakeCredRequest(email, name, database[email].id);
  challengeMakeCred.status = 'ok';

  request.session.challenge = challengeMakeCred.challenge;
  request.session.email = email;

  response.json(challengeMakeCred);
});

router.post('/login', (request, response) => {
  if (!request.body || !request.body.email) {
    response.json({
      status: 'failed',
      message: 'Request missing email field!'
    });

    return;
  }

  const email = request.body.email;

  if (!database[email] || !database[email].registered) {
    response.json({
      status: 'failed',
      message: `User ${email} does not exist!`
    });

    return;
  }

  const getAssertion = generateServerGetAssertion(database[email].authenticators);
  getAssertion.status = 'ok';

  request.session.challenge = getAssertion.challenge;
  request.session.email = email;

  response.json(getAssertion);
});

router.post('/response', (request, response) => {
  if (!request.body || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type || request.body.type !== 'public-key') {
    response.json({
      status: 'failed',
      message: 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
    });

    return;
  }

  const webauthnResp: EncodedPublicKeyCredential = request.body;
  const clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

  /* Check challenge... */
  if (clientData.challenge !== request.session.challenge) {
    response.json({
      status: 'failed',
      message: 'Challenges don\'t match!'
    });
  }

  /* ...and origin */
  if (clientData.origin !== config.origin) {
    response.json({
      status: 'failed',
      message: 'Origins don\'t match!'
    });
  }

  let result;
  if (webauthnResp.response.attestationObject !== undefined) {
    /* This is create cred */
    result = verifyAuthenticatorAttestationResponse(webauthnResp);

    if (result.verified) {
      database[request.session.email].authenticators.push(result.authrInfo);
      database[request.session.email].registered = true;
    }
  } else if (webauthnResp.response.authenticatorData !== undefined) {
    /* This is get assertion */
    result = verifyAuthenticatorAssertionResponse(webauthnResp, database[request.session.email].authenticators);
  } else {
    response.json({
      status: 'failed',
      message: 'Can not determine type of response!'
    });
  }

  if (result.verified) {
    request.session.loggedIn = true;
    response.json({ status: 'ok' });
  } else {
    response.json({
      status: 'failed',
      message: 'Can not authenticate signature!'
    });
  }
});

module.exports = router;
