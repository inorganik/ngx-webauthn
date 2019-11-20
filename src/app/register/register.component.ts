import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators } from '@angular/forms';
import { WebauthnService } from '../webauthn.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent implements OnInit {

  registerGroup: FormGroup;
  error = '';

  constructor(private fb: FormBuilder, private webauthnService: WebauthnService) { }

  ngOnInit() {
    this.registerGroup = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      name: ['', Validators.required]
    });
  }

  submit() {
    this.error = '';
    if (this.registerGroup.valid) {
      this.webauthnService.registerUser(this.registerGroup.value).subscribe(response => {
        if (response.status === 'ok') {
          // todo: route to auth-guarded route
        }
      }, error => this.error = error);
    } else {
      this.error = 'Please correct the errors above.';
    }
  }

}
