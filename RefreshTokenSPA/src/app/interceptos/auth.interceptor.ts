import { Injectable, Injector } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
} from '@angular/common/http';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AuthService } from '../Services/auth.service';
import { Router } from '@angular/router';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private inject: Injector, private authservice: AuthService) {}

  intercept(
    request: HttpRequest<unknown>,
    next: HttpHandler
  ): Observable<HttpEvent<unknown>> {
    if (!this.authservice.IsloggedIn()) {
      return next.handle(request);
    }
    let authreq = request;
    authreq = this.AddTokenheader(request, this.authservice.getToken());
    return next.handle(authreq).pipe(
      catchError((errordata: any) => {
        if (errordata.status === 401) {
          // need to implement logout
          //authservice.LogOut();
          // refresh token logic
          return this.handleRefrehToken(request, next);
        }
        return throwError(errordata);
      })
    );
  }
  handleRefrehToken(request: HttpRequest<any>, next: HttpHandler) {
    let authservice = this.inject.get(AuthService);
    var model = {
      refreshTokenId: localStorage.getItem('refreshTokenId'),
    };
    return authservice.RefreshToken(model).pipe(
      switchMap((data: any) => {
        authservice.SaveTokens(data);
        return next.handle(this.AddTokenheader(request, data.jwtToken));
      }),
      catchError((errodata) => {
        return throwError(errodata);
      })
    );
  }

  AddTokenheader(request: HttpRequest<any>, token: any) {
    return request.clone({
      headers: request.headers.set('Authorization', 'bearer ' + token),
    });
  }
}
