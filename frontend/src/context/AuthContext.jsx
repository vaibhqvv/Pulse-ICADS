import React, { createContext, useContext } from 'react';
import { useAuth } from '../hooks/useAuth';
import LoadingSpinner from '../components/common/LoadingSpinner';
const AuthContext = createContext(null);
export function AuthProvider({ children }) {
  const auth = useAuth();
  if (auth.loading) {
    return <LoadingSpinner fullScreen message="Initializing Pulse..." />;
  }

  return (
    <AuthContext.Provider value={auth}>
      {children}
    </AuthContext.Provider>
  );
}
export function useAuthContext() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuthContext must be used within an AuthProvider');
  }
  return context;
}

export default AuthContext;
