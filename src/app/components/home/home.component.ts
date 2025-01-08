import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import {
  collection,
  collectionData,
  DocumentData,
  Firestore,
} from '@angular/fire/firestore';
import { MatIconModule } from '@angular/material/icon';
import { Router } from '@angular/router';
import { Observable, of } from 'rxjs';

@Component({
  selector: 'app-home',
  imports: [MatIconModule, CommonModule],
  template: `
    <ng-content></ng-content>

    @if(isUserAuthenticated){
    <div class="welcomeBannerStyle">
      <h1>Welcome!</h1>
      <h2>You have successfully signed in.</h2>
      <h2>May the magic begin</h2>
    </div>
    <mat-icon class="signOutButton" (click)="logout()"> logout </mat-icon>
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
  `,
  styleUrl: './home.component.css',
})
export class HomeComponent {
  isUserAuthenticated: any;
  // {" " + cookies.userDetails?.displayName}
  logout() {
    throw new Error('Method not implemented.');
  }
  title = 'newtritionist-app-angular';
  fireStore: Firestore = inject(Firestore);
  router: Router = inject(Router);
  item$: Observable<DocumentData[]> = of([]);

  constructor() {
    const itemCollection = collection(this.fireStore, 'test');
    this.item$ = collectionData<DocumentData>(itemCollection);
  }

  navigateToAuth() {
    console.log('Navigating to auth');
    this.router.navigate(['/login']);
  }
}
