import { createFeatureSelector, createSelector } from '@ngrx/store';
import { AuthState } from '../reducers/auth.reducer';

export const selectAuthState = createFeatureSelector<AuthState>('auth');

export const isAuthenticatedSelector = createSelector(
  selectAuthState,
  (state: AuthState) => state.isAuthenticated
);

export const selectUserInfo = createSelector(
  selectAuthState,
  (state: AuthState) => state.userInfo
);
