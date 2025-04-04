import { inject, signal } from '@angular/core';
import { Auth } from '@angular/fire/auth';
import { CanActivateFn, Router } from '@angular/router';
import { Store } from '@ngrx/store';
import { AuthState } from './store/reducers/auth.reducer';
import { map, take } from 'rxjs';
import { isAuthenticatedSelector } from './store/selectors/auth.selectors';

export const authGuardGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  const store = inject(Store<AuthState>);
  const auth = inject(Auth);
  const isAuthenticated = signal(false);

  // TODO: this is a mess, clean it up

  const canActivate = () => {
    // if (!isAuthenticated()) {
    //   console.log('auth.currentUser is null', auth.currentUser);
    //   router.navigate(['/login']);
    //   return false;
    // }
    return true;
  };

  // auth.onAuthStateChanged((user) => {
  //   if (user) {
  //     isAuthenticated.set(true);
  //   } else {
  //     isAuthenticated.set(false);
  //   }
  // });

  return canActivate();

  // store.select(isAuthenticatedSelector).pipe(
  //   take(1),
  //   map((isAuthenticated) => {
  //     // console.log('isAuthenticated', isAuthenticated);
  //     // console.log('auth.currentUser', auth);
  //     // //TODO: Work around to fix auth without storing in local storage
  //     if (auth.currentUser === null) {
  //       console.log('auth.currentUser is null', auth.currentUser);
  //       router.navigate(['/login']);
  //       return false;
  //     }
  //     return true;
  //   })
  // );
};
