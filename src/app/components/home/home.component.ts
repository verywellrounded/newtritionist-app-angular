import { CommonModule } from '@angular/common';
import { Component, inject, signal } from '@angular/core';
import { Auth } from '@angular/fire/auth';
import {
  collection,
  collectionData,
  DocumentData,
  Firestore,
} from '@angular/fire/firestore';
import { MatIconModule } from '@angular/material/icon';
import { Router } from '@angular/router';
import { Observable, of } from 'rxjs';
import { LayoutComponent } from '../layout/layout.component';

@Component({
  selector: 'app-home',
  imports: [MatIconModule, CommonModule, LayoutComponent],
  template: `
    <app-layout>
      @if(auth.currentUser !== null){
      <div class="welcomeBannerStyle">
        <h1>Welcome!</h1>
        <h2>You have successfully signed in.</h2>
        <h3>May the magic begin</h3>
      </div>
      <div class="signOutButton">
        <mat-icon (click)="logout()"> logout </mat-icon>
      </div>

      }@else{
      <span class="bannerText">
        <h1>Nutritionist</h1>
      </span>
      <button
        mat-raised-button
        variant="contained"
        class="signInButton"
        (click)="navigateToAuth()"
      >
        Login/SignUp
      </button>
      }
    </app-layout>
  `,
  styleUrl: './home.component.css',
})
export class HomeComponent {
  auth = inject(Auth);
  title = 'newtritionist-app-angular';
  fireStore: Firestore = inject(Firestore);
  router: Router = inject(Router);
  item$: Observable<DocumentData[]> = of([]);
  isUserAuthenticated = signal(false);

  constructor() {
    const itemCollection = collection(this.fireStore, 'test');
    this.item$ = collectionData<DocumentData>(itemCollection);
    this.auth.onAuthStateChanged((user) => {
      if (user) {
        this.isUserAuthenticated.set(true);
      } else {
        this.isUserAuthenticated.set(false);
      }
    });
  }
  logout() {
    this.auth.signOut().then(() => {
      this.isUserAuthenticated.set(false);
      this.navigateToAuth();
    });
  }

  navigateToAuth() {
    console.log('Navigating to auth');
    this.router.navigate(['/login']);
  }
}
