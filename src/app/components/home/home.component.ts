import { Component, inject } from '@angular/core';
import {
  collection,
  collectionData,
  DocumentData,
  Firestore,
} from '@angular/fire/firestore';
import { Router } from '@angular/router';
import { Observable, of } from 'rxjs';

@Component({
  selector: 'app-home',
  imports: [],
  template: `<div>
    <span className="bannerText">
      <h1>Nutritionist</h1>
    </span>
    <Button variant="contained" className="signInButton">
      <a href="/login"> Login/SignUp </a>
    </Button>
  </div>`,
  styleUrl: './home.component.css',
})
export class HomeComponent {
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
