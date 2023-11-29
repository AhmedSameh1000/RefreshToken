import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Router } from '@angular/router';
import { switchMap } from 'rxjs';

@Injectable({
  providedIn: 'root',
})
export class AuthService {
  constructor(private http: HttpClient, private Route: Router) {}

  login(Login: any) {
    return this.http.post('https://localhost:7180/api/Auth/token', Login);
  }
  Register(Signup: any) {
    return this.http.post('https://localhost:7180/api/Auth/register', Signup);
  }
  IsloggedIn() {
    try {
      const token: any = this.getToken();
      return token;
    } catch {
      return false;
    }
  }
  getToken() {
    return localStorage.getItem('token');
  }
  LogOut() {
    localStorage.clear();
    this.Route.navigate(['']);
  }
  GetNames() {
    return this.http.get('https://localhost:7180/api/Secured');
  }
  RefreshToken(model: any) {
    return this.http.post(
      'https://localhost:7180/api/Auth/refreshToken',
      model
    );
  }
  RevokeToken(model: any) {
    return this.http.post('https://localhost:7180/api/Auth/revokeToken', model);
  }
  SaveTokens(tokendata: any) {
    localStorage.setItem('token', tokendata.token);
    localStorage.setItem('refreshTokenId', tokendata.refreshTokenId);
  }
}
