import { Component, OnInit } from '@angular/core';
import { WebauthnService } from '../webauthn/webauthn.service';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit {

  constructor(private webauthnService: WebauthnService) { }

  ngOnInit() {
  }

  logout() {
    this.webauthnService.logout().subscribe();
  }

}
