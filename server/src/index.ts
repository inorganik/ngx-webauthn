import * as express from 'express';
import * as path from 'path';
import * as bodyParser from 'body-parser';
import * as cookieSession from 'cookie-session';
import * as cookieParser from 'cookie-parser';
import * as crypto from 'crypto';
import * as WebAuthn from 'webauthn';

// app
const port = process.env.PORT || 3000;
const app = express();
app.use(bodyParser.json());

// session
app.use(cookieSession({
  name: 'session',
  keys: [crypto.randomBytes(32).toString('hex')],
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));
app.use(cookieParser());

// serve angular app
app.use(express.static(path.join(__dirname, '../../dist/ngx-webauthn')));

// webauthn routes
const webauthn = new WebAuthn({
  origin: `http://localhost:4200`,
  usernameField: 'email', // field that uniquely id's user
  userFields: {
    email: 'email',
    name: 'displayName',
  },
  // using default in-memory "db"
  // OR
  // store: {
  //   put: async (id, value) => void,
  //   get: async (id) => User,
  //   search: async (search) =>  { [username]: User },
  //   delete: async (id) => boolean,
  // },
  rpName: 'Inorganik Produce, inc.',
});
app.use('/webauthn', webauthn.initialize());

// init
app.listen(port, () => console.log(`Server listening on port ${port}!`));
