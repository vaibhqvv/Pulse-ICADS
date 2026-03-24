import { useState, useEffect, useCallback } from 'react';
import {
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  updatePassword as firebaseUpdatePassword,
  reauthenticateWithCredential,
  EmailAuthProvider,
} from 'firebase/auth';
import { auth } from '../firebase/config';
export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);  // True until Firebase resolves auth
  const [error, setError] = useState(null);
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (firebaseUser) => {
      setUser(firebaseUser);
      setLoading(false);
    });

    return () => unsubscribe();
  }, []);
  const login = useCallback(async (email, password) => {
    setError(null);
    setLoading(true);
    try {
      const result = await signInWithEmailAndPassword(auth, email, password);
      setUser(result.user);
      return result.user;
    } catch (err) {
      const message = getAuthErrorMessage(err.code);
      setError(message);
      throw new Error(message);
    } finally {
      setLoading(false);
    }
  }, []);
  const logout = useCallback(async () => {
    try {
      await signOut(auth);
      setUser(null);
    } catch (err) {
      setError('Failed to sign out');
      console.error('Logout error:', err);
    }
  }, []);
  const changePassword = useCallback(async (currentPassword, newPassword) => {
    if (!user) throw new Error('Not authenticated');

    try {
      // Re-authenticate first (required by Firebase for sensitive operations)
      const credential = EmailAuthProvider.credential(user.email, currentPassword);
      await reauthenticateWithCredential(auth.currentUser, credential);
      await firebaseUpdatePassword(auth.currentUser, newPassword);
    } catch (err) {
      const message = getAuthErrorMessage(err.code);
      throw new Error(message);
    }
  }, [user]);
  const clearError = useCallback(() => setError(null), []);

  return { user, loading, error, login, logout, changePassword, clearError };
}
function getAuthErrorMessage(errorCode) {
  const messages = {
    'auth/invalid-email': 'Invalid email address',
    'auth/user-disabled': 'This account has been disabled',
    'auth/user-not-found': 'No account found with this email',
    'auth/wrong-password': 'Incorrect password',
    'auth/invalid-credential': 'Invalid credentials. Please check your email and password.',
    'auth/too-many-requests': 'Too many failed attempts. Please try again later.',
    'auth/network-request-failed': 'Network error. Check your internet connection.',
    'auth/weak-password': 'Password must be at least 6 characters',
    'auth/requires-recent-login': 'Please log in again before changing your password',
  };
  return messages[errorCode] || 'Authentication failed. Please try again.';
}

export default useAuth;
