import { createReducer, on } from '@ngrx/store';
import { login, logout } from '../actions/auth.actions';

export interface AuthState {
  isAuthenticated: boolean;
  userInfo: any;
}

export const initialState: AuthState = {
  isAuthenticated: false,
  userInfo: null,
};

export const authReducer = createReducer(
  initialState,
  on(login, (state, { userInfo }) => ({
    ...state,
    isAuthenticated: true,
    userInfo,
  })),
  on(logout, (state) => ({
    ...state,
    isAuthenticated: false,
    userInfo: null,
  }))
);
