import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import {
  collection,
  collectionData,
  DocumentData,
  Firestore,
} from '@angular/fire/firestore';
import { Router, RouterOutlet } from '@angular/router';
import { Observable, of } from 'rxjs';

@Component({
  selector: 'app-root',
  imports: [CommonModule, RouterOutlet],
  template: `
    <div>
      <span className="bannerText">
        <h1>Nutritionist</h1>
      </span>
      <Button variant="contained" className="signInButton">
        <a href="/login"> Login/SignUp </a>
      </Button>
    </div>
    <router-outlet> </router-outlet>
  `,
  styleUrl: './app.component.css',
})
export class AppComponent {
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
