import { NgOptimizedImage } from '@angular/common';
import { Component, inject } from '@angular/core';

import { AuthService } from '../../services/auth.service';

@Component({
  selector: 'app-login',
  imports: [NgOptimizedImage],
  template: ` <h1 class="bannerText">Authentication Page</h1>
    <div class="signupContainer__box__google">
      //TODO: Wanna change this so the text is below the icon but this will do
      for now
      <Button (click)="handleGoogleSignUp($event)" variant="contained">
        <span>
          <img
            ngSrc="assets/1844710_grape_nutrition_food_icon.svg"
            height="200"
            width="200"
            alt="Grape Logo"
          />
        </span>
        Sign Up with Google
      </Button>
      @if(authService.error){
      <p>(googleErrorMessage)</p>
      }
    </div>`,
  standalone: true,
  styleUrl: './auth.component.css',
})
export class AuthComponent {
  authService: AuthService = inject(AuthService);
  handleGoogleSignUp(event: Event) {
    console.log('Clicked');
    this.authService.handleGoogleSignUp(event);
  }
}
