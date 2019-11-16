// proxy for local environment: allows server to run on separate port

const PROXY_CONFIG = [
  {
    context: ['/webauthn'],
    target: 'http://localhost:3000',
    secure: false,
  },
];

module.exports = PROXY_CONFIG;
