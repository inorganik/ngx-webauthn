# Webauthn with Angular

A full-stack demo of using [Webauthn](https://en.wikipedia.org/wiki/WebAuthn) with Angular. This is a simple app that just includes a login page, register page, and auth-protected home page.

Check out the slides from my [WebAuthn talk](https://docs.google.com/presentation/d/1k6KCKgZl_uOxV79X-8RWr_VMVROtnpq7OXTrGw4CXTI/edit?usp=sharing).

### The server

The node server handles `/webauthn` routes via the [webauthn](https://github.com/strangerlabs/webauthn) node package, which is nice packaging of Yuriy Ackermann's fantastic [webauthn demo](https://github.com/fido-alliance/webauthn-demo) repo. Yuriy's repo includes a great tutorial for building the backend yourself in node, which I suggest you try. The node webauthn package also includes a client, but it is not used here. Aside from some utility functions, the client code is written from scratch, and it all resides in [webauthn.service.ts](src/app/webauthn/webauthn.service.ts).

### Do I need a security key?

In production, you'll need a security key like a [Yubikey](https://www.yubico.com/store/) or a [Google Titan key](https://cloud.google.com/titan-security-key/), **OR** a Macbook Pro with TouchID. But for development, if you have neither of those you can simply use the [Virtual Authenticator Chrome extension](https://github.com/google/virtual-authenticators-tab).

To use the virtual authenticator, set the protocol to `u2f` and click "Add". When you register it won't test for user presence but it will let you inspect the stored credential.

### Run locally

For local development, the app runs on localhost:4200 and server routes are proxied to port 3000:

1. `npm start` or `ng s` - run angular client app.
1. `npm run server:watch` - run node server.
1. Open http://localhost:4200 

Test prod build (won't be able to login because of origin mismatch):

1. `npm run build`
1. `npm run server:build`
1. `node dist/index.js`
1. Open http://localhost:3000

---

The client app was generated with [Angular CLI](https://github.com/angular/angular-cli) version 8.3.9.

MIT license.
