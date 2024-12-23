import { CommonModule } from '@angular/common';
import { Component, inject } from '@angular/core';
import {
  collection,
  collectionData,
  DocumentData,
  Firestore,
} from '@angular/fire/firestore';
import { Observable, of } from 'rxjs';

@Component({
  selector: 'app-root',
  imports: [CommonModule],
  template: `
    <ul>
      @for (item of (item$ | async); track item) {
      <li>
        {{ item['name'] }}
      </li>
      }
    </ul>
  `,
  styleUrl: './app.component.css',
})
export class AppComponent {
  title = 'newtritionist-app-angular';
  fireStore: Firestore = inject(Firestore);
  item$: Observable<DocumentData[]> = of([]);

  constructor() {
    const itemCollection = collection(this.fireStore, 'test');
    this.item$ = collectionData<DocumentData>(itemCollection);
  }
}
