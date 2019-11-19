import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpErrorResponse } from '@angular/common/http';
import { catchError } from 'rxjs/operators';
import { throwError, Observable } from 'rxjs';
import { MakePublicKeyCredentialOptions } from './webauthn.models';

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

  registerUser(user: User): Observable<MakePublicKeyCredentialOptions> {
    const url = `${this.pathPrefix}/register`;
    const opts = {
      headers: new HttpHeaders({
        'Content-Type': 'application/json'
      })
    };
    return this.http.post<MakePublicKeyCredentialOptions>(url, user, opts).pipe(
      catchError(err => this.handleError(err))
    );
  }

  private handleError(error: HttpErrorResponse) {
    if (error.error instanceof ErrorEvent) {
      // A client-side or network error occurred. Handle it accordingly.
      console.error('An error occurred:', error.error.message);
    } else {
      // The backend returned an unsuccessful response code.
      console.error(
        `Server returned a ${error.status}, ` +
        `body was: ${error.error}`);
    }
    // return an observable with a user-facing error message
    return throwError(error);
  };
}
