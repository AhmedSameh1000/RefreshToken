import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { AuthService } from '../Services/auth.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css'],
})
export class HomeComponent implements OnInit {
  constructor(private Auth: AuthService) {}
  ngOnInit(): void {
    this.GetNames();
  }

  Names: [] = [];
  GetNames() {
    this.Auth.GetNames().subscribe((res: any) => {
      console.log(res);
      this.Names = res;
    });
  }
}
