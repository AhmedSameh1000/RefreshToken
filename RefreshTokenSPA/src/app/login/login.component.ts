import { Component } from '@angular/core';
import { AuthService } from '../Services/auth.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
})
export class LoginComponent {
  constructor(private AuthService: AuthService, private Rout: Router) {}

  Email: string = '';
  Password: string = '';
  logIn() {
    var model = {
      Email: this.Email,
      Password: this.Password,
    };
    this.AuthService.login(model).subscribe((res: any) => {
      console.log(res);
      this.AuthService.SaveTokens(res);
      this.Rout.navigate(['']);
    });
  }
}
