import {
  ApplicationConfig,
  isDevMode,
  provideZoneChangeDetection,
} from '@angular/core';
import { provideRouter } from '@angular/router';

import { getAnalytics, provideAnalytics } from '@angular/fire/analytics';
import { initializeApp, provideFirebaseApp } from '@angular/fire/app';
import { getAuth, provideAuth } from '@angular/fire/auth';
import { getFirestore, provideFirestore } from '@angular/fire/firestore';
import {
  provideClientHydration,
  withEventReplay,
} from '@angular/platform-browser';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideEffects } from '@ngrx/effects';
import { provideStore } from '@ngrx/store';
import { provideStoreDevtools } from '@ngrx/store-devtools';
import { routes } from './app.routes';
import { authReducer, AuthState } from './store/reducers/auth.reducer';

const firebaseConfig = {
  apiKey: 'AIzaSyApeHp8f3VbMir4QeabWv-tBG8gbPjh6-0',
  authDomain: 'newtritionist-app-angular.firebaseapp.com',
  projectId: 'newtritionist-app-angular',
  storageBucket: 'newtritionist-app-angular.firebasestorage.app',
  messagingSenderId: '427778759049',
  appId: '1:427778759049:web:85c1f4d118ca80fe81a958',
  measurementId: 'G-9T4ZYPKPDK',
};

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideClientHydration(withEventReplay()),
    provideFirebaseApp(() => initializeApp(firebaseConfig)),
    provideAuth(() => getAuth()),
    provideFirestore(() => getFirestore()),
    provideAnalytics(() => getAnalytics()),
    provideAnimationsAsync(),
    provideStore<{ auth: AuthState }>({ auth: authReducer }), // standalone way of registering store
    provideEffects(),
    provideStoreDevtools({ maxAge: 25, logOnly: !isDevMode() }),
  ],
};
