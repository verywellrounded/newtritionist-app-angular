import { inject } from '@angular/core';
import { Auth } from '@angular/fire/auth';
import { CanActivateFn, Router } from '@angular/router';
import { Store } from '@ngrx/store';
import { AuthState } from './store/reducers/auth.reducer';
import { map, take } from 'rxjs';
import { isAuthenticatedSelector } from './store/selectors/auth.selectors';

export const authGuardGuard: CanActivateFn = (route, state) => {
  const router = inject(Router);
  const store = inject(Store<AuthState>);

  return store.select(isAuthenticatedSelector).pipe(
    take(1),
    map((isAuthenticated) => {
      if (!isAuthenticated) {
        router.navigate(['/login']);
        return false;
      }
      return true;
    })
  );
};
