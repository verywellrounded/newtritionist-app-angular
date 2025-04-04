import { createAction, props } from '@ngrx/store';

export const login = createAction('[Auth] Login', props<{ userInfo: any }>());
export const logout = createAction('[Auth] Logout');
