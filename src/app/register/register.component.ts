import { Component, OnInit } from '@angular/core';
import { FormGroup, FormBuilder, Validators, AbstractControl } from '@angular/forms';
import { WebauthnService } from '../webauthn/webauthn.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export class RegisterComponent implements OnInit {

  registerGroup: FormGroup;
  error = '';
  submitted = false;

  constructor(
    private fb: FormBuilder,
    private webauthnService: WebauthnService,
    private router: Router
  ) { }

  ngOnInit() {
    this.registerGroup = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      name: ['', Validators.required]
    });

    if (!this.webauthnService.isSupported()) {
      this.error = 'Web Authentication is not supported in this browser.';
    }
  }

  submit() {
    this.error = '';
    this.submitted = true;
    if (this.registerGroup.valid) {
      this.webauthnService.registerUser(this.registerGroup.value).subscribe(response => {
        if (response.status === 'ok') {
          this.router.navigate(['/']);
        }
      }, error => this.error = error);
    } else {
      this.error = 'Please correct any errors above.';
    }
  }

  showError(controlName: string): boolean {
    const ctrl: AbstractControl = this.registerGroup.controls[controlName];
    return (ctrl.touched && ctrl.invalid) || (this.submitted && ctrl.invalid);
  }

}
