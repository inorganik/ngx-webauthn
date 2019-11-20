/// <reference types="@types/webappsec-credential-management" />

import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { catchError, switchMap } from 'rxjs/operators';
import { throwError, Observable } from 'rxjs';
import { PublicKeyCredentialOptions } from './webauthn.models';
import base64url from 'webauthn/client/base64url.js';

export interface User {
  email: string;
  name: string;
}

@Injectable({
  providedIn: 'root'
})
export class WebauthnService {

  pathPrefix = '/webauthn';

  constructor(private http: HttpClient) { }

  registerUser(user: User): Observable<any> {
    return this.post<PublicKeyCredentialOptions>('/register', user).pipe(
      switchMap(async response => {
        console.log('response', response);
        const publicKey = this.preformatMakeCredReq(response);
        console.log('publicKey', publicKey);
        return navigator.credentials.create({ publicKey });
      }),
      switchMap(result => {
        console.log('result', result);
        const makeCredResponse = this.publicKeyCredentialToJSON(result);
        console.log('make cred response', makeCredResponse);
        return this.post('/response', makeCredResponse);
      })
    );
  }


  // UTILITIES

  private post<T>(endpoint: string, body: any): Observable<T> {
    const url = this.pathPrefix + endpoint;
    const opts = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json'
      })
    };
    return this.http.post<T>(url, body, opts).pipe(
      catchError(err => this.handleError(err))
    );
  }

  private handleError(error: HttpErrorResponse) {
    console.error('Request error', error.error);
    let errMsg;
    if (error.error instanceof ErrorEvent) {
      // A client-side or network error occurred. Handle it accordingly.
      errMsg = error.error.message;
    } else {
      // The backend returned an unsuccessful response code.
      const err = error.error;
      let msg;
      if (typeof err === 'string') {
        msg = err;
      } else if (err.message) {
        msg = err.message;
      } else {
        msg = JSON.stringify(err);
      }
      errMsg = `${error.status}: ${msg}`;
    }
    // return an observable with a user-facing error message
    return throwError(errMsg);
  }

  /**
   * Converts PublicKeyCredential into serialised JSON
   */
  private publicKeyCredentialToJSON(pubKeyCred: any) {
    if (Array.isArray(pubKeyCred)) {
      return pubKeyCred.map(i => this.publicKeyCredentialToJSON(i));
    }
    if (pubKeyCred instanceof ArrayBuffer) {
      return base64url.encode(pubKeyCred);
    }
    if (pubKeyCred instanceof Object) {
      const obj = {};
      for (const key in pubKeyCred) {
        if (pubKeyCred[key]) {
          obj[key] = this.publicKeyCredentialToJSON(pubKeyCred[key]);
        }
      }
      return obj;
    }
    return pubKeyCred;
  }

  /**
   * Decodes arrayBuffer required fields.
   */
  private preformatMakeCredReq(makeCredReq) {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id);
    return makeCredReq;
  }

  /**
   * Decodes arrayBuffer required fields.
   */
  private preformatGetAssertReq(getAssert) {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    for (const allowCred of getAssert.allowCredentials) {
      allowCred.id = base64url.decode(allowCred.id);
    }
    return getAssert;
  }

}
