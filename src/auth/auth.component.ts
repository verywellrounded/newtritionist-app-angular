import { NgOptimizedImage } from '@angular/common';
import { Component, inject } from '@angular/core';
import {
  Firestore,
  addDoc,
  collection,
  doc,
  getDocs,
  query,
  updateDoc,
  where,
} from '@angular/fire/firestore';
// import { Router } from '@angular/router';
import {
  Auth,
  getRedirectResult,
  GoogleAuthProvider,
  signInWithPopup,
  signInWithRedirect,
  User,
  UserCredential,
} from '@angular/fire/auth';

@Component({
  selector: 'app-login',
  imports: [NgOptimizedImage],
  template: ` <div>
    <h1 className="bannerText">Authentication Page</h1>
    <div className="signupContainer__box__google">
      //TODO: Wanna change this so the text is below the icon but this will do
      for now
      <Button (onClick)="handleGoogleSignUp($event)" variant="contained">
        <span>
          <img
            ngSrc="assets/1844710_grape_nutrition_food_icon.svg"
            height="200"
            width="200"
            alt="Grape Logo"
          />
        </span>
        Sign Up with Google
      </Button>
      @if(this.error){
      <p>(googleErrorMessage)</p>
      }
    </div>
  </div>`,
  standalone: true,
  styleUrl: './auth.component.css',
})
export class AuthComponent {
  db: Firestore = inject(Firestore);
  auth: Auth = inject(Auth);
  cookie: Map<String, {}> = new Map();
  googleErrorMessage: string = '';
  error: boolean = false;
  // router: Router = inject(Router);

  log = () => {
    console.log('Logging');
  };

  saveUserInfo = async (user: User) => {
    try {
      //TODO: Could caching be implemented here to save of reads/ writes ?
      //TODO: put get db in service
      const usersCollection = collection(this.db, 'users');
      const q = query(usersCollection, where('email', '==', user.email));
      // Check if user is already stored
      const querySnapshot = await getDocs(q);
      if (!querySnapshot.empty) {
        // If so then update last login
        const docId = querySnapshot.docs[0].id;
        await updateDoc(doc(this.db, 'users', docId), {
          lastLogin: user.metadata.lastSignInTime,
        });
        console.log('Updated written with ID: ', docId);
      } else {
        //If not save
        const docRef = await addDoc(usersCollection, {
          uid: user.uid,
          displayName: user.displayName,
          email: user.email,
          created: user.metadata.creationTime,
          lastLogin: user.metadata.lastSignInTime,
          providerId: user.providerId,
        });
        console.log('Document written with ID: ', docRef.id);
      }
    } catch (e) {
      console.error('Error adding document: ', e);
    }
    console.log('Signed in user creds', user);
  };

  // Handle user sign up with google
  handleGoogleSignUp = async (e: any) => {
    e.preventDefault();
    this.log();
    // Instantiate a GoogleAuthProvider object
    const provider = new GoogleAuthProvider();
    let result: UserCredential | null = null;
    try {
      // Sign in with a pop-up window
      // 💡Sign in with popup seems less error prone and still a smooth expereince
      console.log('Trying to sign in with popup');
      result = await signInWithPopup(this.auth, provider);

      // Pull signed-in user credential.
      const user = result.user;
      console.log('Signed in result', result);
      await this.saveUserInfo(user);
      this.cookie.set('userDetails', {
        uid: user.uid,
        displayName: user.displayName,
        token: user.getIdToken(false),
      });
      // this.router.navigateByUrl('/');
    } catch (err: any) {
      // Handle errors here.
      const errorMessage = err.message;
      const errorCode = err.code;

      this.error = true;

      switch (errorCode) {
        case 'auth/operation-not-allowed':
          this.googleErrorMessage = 'Email/password accounts are not enabled.';
          break;
        case 'auth/operation-not-supported-in-this-environment':
          this.googleErrorMessage =
            'HTTP protocol is not supported. Please use HTTPS.';
          break;
        case 'auth/popup-blocked':
          console.log('Pop up blocked. Trying redirect');
          await signInWithRedirect(this.auth, provider);
          result = await getRedirectResult(this.auth);

          // this.googleErrorMessage =
          //   "Popup has been blocked by the browser. Please allow popups for this website."
          // ;
          break;
        case 'auth/popup-closed-by-user':
          this.googleErrorMessage =
            'Popup has been closed by the user before finalizing the operation. Please try again.';
          break;
        default:
          this.googleErrorMessage = errorMessage;
          break;
      }
    }

    if (null !== result) {
      const user = result.user;
      console.log('Signed in result', result);
      this.saveUserInfo(user);
    } else {
      console.log('login failed. Result is null', result);
    }
    // this.router.navigateByUrl('/');
  };
}
