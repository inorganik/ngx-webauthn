import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators, AbstractControl } from '@angular/forms';
import { WebauthnService } from '../webauthn/webauthn.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {

  loginGroup: FormGroup;
  error = '';
  submitted = false;

  constructor(
    private fb: FormBuilder,
    private webauthnService: WebauthnService,
    private router: Router
  ) { }

  ngOnInit() {
    this.loginGroup = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
    });

    if (!this.webauthnService.isSupported()) {
      this.error = 'Web Authentication is not supported in this browser.';
    }
  }

  submit() {
    this.error = '';
    this.submitted = true;
    if (this.loginGroup.valid) {
      this.webauthnService.loginUser(this.loginGroup.value).subscribe(response => {
        console.log('response', response);
        if (response.status === 'ok') {
          this.router.navigate(['/']);
        }
      }, error => this.error = error);
    } else {
      this.error = 'Please correct any errors above.';
    }
  }

  showError(controlName: string): boolean {
    const ctrl: AbstractControl = this.loginGroup.controls[controlName];
    return (ctrl.touched && ctrl.invalid) || (this.submitted && ctrl.invalid);
  }

}
