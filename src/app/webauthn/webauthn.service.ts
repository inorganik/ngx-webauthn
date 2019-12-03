/// <reference types="@types/webappsec-credential-management" />

/**
 * WebAuthn Angular service for use with node 'webauthn' package
 *
 * Author: Jamie Perkins
 * License: MIT
 */

import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { catchError, switchMap, map, tap } from 'rxjs/operators';
import { throwError, Observable, of } from 'rxjs';
import { PublicKeyCredentialOptions } from './webauthn.models';
import base64url from 'webauthn/client/base64url.js';
import { Router } from '@angular/router';

export interface User {
  email: string;
  name?: string;
}

export interface StatusResponse {
  status: string;
  message?: string;
}

@Injectable({
  providedIn: 'root'
})
export class WebauthnService {

  pathPrefix = '/webauthn'; // where you serve your webauthn routes
  noAuthPath = '/login'; // where to redirect unauthenticated users

  constructor(private http: HttpClient, private router: Router) { }

  registerUser(user: User): Observable<StatusResponse> {
    return this.post<PublicKeyCredentialOptions>('/register', user).pipe(
      switchMap(async response => {
        const publicKey = this.preformatMakeCredReq(response);
        console.log('register: make cred request:', publicKey);
        return navigator.credentials.create({ publicKey });
      }),
      switchMap(result => this.sendWebauthnResponse(result))
    );
  }

  loginUser(user: User): Observable<StatusResponse> {
    return this.post<PublicKeyCredentialOptions>('/login', user).pipe(
      switchMap(async response => {
        const publicKey = this.preformatGetAssertReq(response);
        console.log('login: get assertion request', publicKey);
        return navigator.credentials.get({ publicKey });
      }),
      switchMap(result => this.sendWebauthnResponse(result))
    );
  }

  authCheck(): Observable<boolean> {
    const opts = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json'
      })
    };
    return this.http.get<StatusResponse>('/auth-check', opts).pipe(
      map(response => {
        if (response.status && response.status === 'ok') {
          return true;
        } else {
          return false;
        }
      }),
      catchError(err => of(false))
    );
  }

  logout(): Observable<StatusResponse> {
    return this.post<StatusResponse>('/logout', {}).pipe(
      tap(() => this.router.navigateByUrl(this.noAuthPath))
    );
  }

  isSupported(): boolean {
    return navigator && !!navigator.credentials;
  }

  // UTILITIES

  private sendWebauthnResponse(cred: CredentialType): Observable<StatusResponse> {
    const makeCredResponse = this.publicKeyCredentialToJSON(cred);
    console.log('make cred response', makeCredResponse);
    return this.post('/response', makeCredResponse);
  }

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
   * Decodes array buffers in make credential request
   */
  private preformatMakeCredReq(makeCredReq) {
    makeCredReq.challenge = base64url.decode(makeCredReq.challenge);
    makeCredReq.user.id = base64url.decode(makeCredReq.user.id);
    return makeCredReq;
  }

  /**
   * Decodes array buffer in get assertion request
   */
  private preformatGetAssertReq(getAssert) {
    getAssert.challenge = base64url.decode(getAssert.challenge);
    for (const allowCred of getAssert.allowCredentials) {
      allowCred.id = base64url.decode(allowCred.id);
    }
    return getAssert;
  }

}
