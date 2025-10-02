import React, { createContext, useContext, useReducer, useEffect } from 'react';
import { authAPI } from '../services/api';
import toast from 'react-hot-toast';

// Auth context
const AuthContext = createContext();

// Auth actions
const AUTH_ACTIONS = {
  LOGIN_START: 'LOGIN_START',
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  REGISTER_START: 'REGISTER_START',
  REGISTER_SUCCESS: 'REGISTER_SUCCESS',
  REGISTER_FAILURE: 'REGISTER_FAILURE',
  SET_USER: 'SET_USER',
  SET_LOADING: 'SET_LOADING',
  CLEAR_ERROR: 'CLEAR_ERROR',
  MFA_REQUIRED: 'MFA_REQUIRED',
  MFA_SUCCESS: 'MFA_SUCCESS',
};

// Initial state
const initialState = {
  user: null,
  isAuthenticated: false,
  isLoading: true,
  error: null,
  mfaRequired: false,
  tempAuthData: null,
};

// Auth reducer
function authReducer(state, action) {
  switch (action.type) {
    case AUTH_ACTIONS.LOGIN_START:
    case AUTH_ACTIONS.REGISTER_START:
      return {
        ...state,
        isLoading: true,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_SUCCESS:
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        isLoading: false,
        error: null,
        mfaRequired: false,
        tempAuthData: null,
      };

    case AUTH_ACTIONS.REGISTER_SUCCESS:
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        isLoading: false,
        error: null,
      };

    case AUTH_ACTIONS.LOGIN_FAILURE:
    case AUTH_ACTIONS.REGISTER_FAILURE:
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        isLoading: false,
        error: action.payload,
        mfaRequired: false,
        tempAuthData: null,
      };

    case AUTH_ACTIONS.MFA_REQUIRED:
      return {
        ...state,
        isLoading: false,
        mfaRequired: true,
        tempAuthData: action.payload,
        error: null,
      };

    case AUTH_ACTIONS.MFA_SUCCESS:
      return {
        ...state,
        isAuthenticated: true,
        user: action.payload.user,
        isLoading: false,
        mfaRequired: false,
        tempAuthData: null,
        error: null,
      };

    case AUTH_ACTIONS.LOGOUT:
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        isLoading: false,
        error: null,
        mfaRequired: false,
        tempAuthData: null,
      };

    case AUTH_ACTIONS.SET_USER:
      return {
        ...state,
        user: action.payload,
        isAuthenticated: !!action.payload,
        isLoading: false,
      };

    case AUTH_ACTIONS.SET_LOADING:
      return {
        ...state,
        isLoading: action.payload,
      };

    case AUTH_ACTIONS.CLEAR_ERROR:
      return {
        ...state,
        error: null,
      };

    default:
      return state;
  }
}

// Auth provider component
export function AuthProvider({ children }) {
  const [state, dispatch] = useReducer(authReducer, initialState);

  // Initialize auth state on mount
  useEffect(() => {
    initializeAuth();
  }, []);

  // Initialize authentication state
  const initializeAuth = async () => {
    try {
      const token = localStorage.getItem('accessToken');
      const user = localStorage.getItem('user');

      if (token && user) {
        try {
          // Verify token with server
          const response = await authAPI.getProfile();
          dispatch({
            type: AUTH_ACTIONS.SET_USER,
            payload: response.data.data.user,
          });
        } catch (error) {
          // Token is invalid, clear stored data
          clearAuthData();
          dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
        }
      } else {
        dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
      }
    } catch (error) {
      console.error('Auth initialization error:', error);
      clearAuthData();
      dispatch({ type: AUTH_ACTIONS.SET_LOADING, payload: false });
    }
  };

  // Clear authentication data
  const clearAuthData = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('user');
  };

  // Store authentication data
  const storeAuthData = (tokens, user) => {
    localStorage.setItem('accessToken', tokens.accessToken);
    localStorage.setItem('refreshToken', tokens.refreshToken);
    localStorage.setItem('user', JSON.stringify(user));
  };

  // Login function
  const login = async (credentials) => {
    try {
      dispatch({ type: AUTH_ACTIONS.LOGIN_START });

      const response = await authAPI.login(credentials);
      const { user, tokens } = response.data.data;

      // Check if MFA is required
      if (response.data.mfaRequired) {
        dispatch({
          type: AUTH_ACTIONS.MFA_REQUIRED,
          payload: { credentials, message: response.data.message },
        });
        return { mfaRequired: true };
      }

      // Store auth data
      storeAuthData(tokens, user);

      dispatch({
        type: AUTH_ACTIONS.LOGIN_SUCCESS,
        payload: { user },
      });

      toast.success('Login successful!');
      return { success: true, user };

    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Login failed';
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: errorMessage,
      });

      toast.error(errorMessage);
      throw error;
    }
  };

  // Login with MFA
  const loginWithMFA = async (mfaToken) => {
    try {
      dispatch({ type: AUTH_ACTIONS.LOGIN_START });

      const credentials = { ...state.tempAuthData.credentials, mfaToken };
      const response = await authAPI.login(credentials);
      const { user, tokens } = response.data.data;

      // Store auth data
      storeAuthData(tokens, user);

      dispatch({
        type: AUTH_ACTIONS.MFA_SUCCESS,
        payload: { user },
      });

      toast.success('Login successful!');
      return { success: true, user };

    } catch (error) {
      const errorMessage = error.response?.data?.message || 'MFA verification failed';
      
      dispatch({
        type: AUTH_ACTIONS.LOGIN_FAILURE,
        payload: errorMessage,
      });

      toast.error(errorMessage);
      throw error;
    }
  };

  // Register function
  const register = async (userData) => {
    try {
      dispatch({ type: AUTH_ACTIONS.REGISTER_START });

      const response = await authAPI.register(userData);
      const { user, tokens } = response.data.data;

      // Store auth data
      storeAuthData(tokens, user);

      dispatch({
        type: AUTH_ACTIONS.REGISTER_SUCCESS,
        payload: { user },
      });

      toast.success('Registration successful!');
      return { success: true, user };

    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Registration failed';
      
      dispatch({
        type: AUTH_ACTIONS.REGISTER_FAILURE,
        payload: errorMessage,
      });

      toast.error(errorMessage);
      throw error;
    }
  };

  // Logout function
  const logout = async () => {
    try {
      const refreshToken = localStorage.getItem('refreshToken');
      
      if (refreshToken) {
        await authAPI.logout(refreshToken);
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // Clear auth data regardless of API call success
      clearAuthData();
      
      dispatch({ type: AUTH_ACTIONS.LOGOUT });
      toast.success('Logged out successfully');
    }
  };

  // Update user profile
  const updateUser = (updatedUser) => {
    localStorage.setItem('user', JSON.stringify(updatedUser));
    dispatch({
      type: AUTH_ACTIONS.SET_USER,
      payload: updatedUser,
    });
  };

  // Clear error
  const clearError = () => {
    dispatch({ type: AUTH_ACTIONS.CLEAR_ERROR });
  };

  // Check if user has specific role
  const hasRole = (role) => {
    return state.user?.role === role;
  };

  // Check if user has specific permission
  const hasPermission = (resource, action) => {
    if (!state.user?.permissions) return false;
    
    return state.user.permissions.some(
      permission => 
        permission.resource === resource && 
        permission.actions.includes(action)
    );
  };

  // Check if user is admin
  const isAdmin = () => {
    return ['admin', 'super_admin'].includes(state.user?.role);
  };

  // Get security level based on user's security features
  const getSecurityLevel = () => {
    if (!state.user) return 'low';
    
    let score = 0;
    
    // MFA enabled
    if (state.user.mfa?.enabled) score += 2;
    
    // Recent password change (within 90 days)
    const lastPasswordChange = new Date(state.user.security?.lastPasswordChange);
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    if (lastPasswordChange > ninetyDaysAgo) score += 1;
    
    // Email verified
    if (state.user.emailVerified) score += 1;
    
    // Phone verified
    if (state.user.phoneVerified) score += 1;
    
    if (score >= 4) return 'high';
    if (score >= 2) return 'medium';
    return 'low';
  };

  const value = {
    // State
    ...state,
    
    // Actions
    login,
    loginWithMFA,
    register,
    logout,
    updateUser,
    clearError,
    
    // Utilities
    hasRole,
    hasPermission,
    isAdmin,
    getSecurityLevel,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// Custom hook to use auth context
export function useAuth() {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
}

// HOC for protecting routes
export function withAuth(Component) {
  return function AuthenticatedComponent(props) {
    const { isAuthenticated, isLoading } = useAuth();
    
    if (isLoading) {
      return (
        <div className="min-h-screen flex items-center justify-center">
          <div className="spinner w-8 h-8"></div>
        </div>
      );
    }
    
    if (!isAuthenticated) {
      window.location.href = '/login';
      return null;
    }
    
    return <Component {...props} />;
  };
}

// HOC for role-based access
export function withRole(allowedRoles) {
  return function (Component) {
    return function RoleProtectedComponent(props) {
      const { user, hasRole } = useAuth();
      
      const hasAccess = allowedRoles.some(role => hasRole(role));
      
      if (!hasAccess) {
        return (
          <div className="min-h-screen flex items-center justify-center">
            <div className="text-center">
              <h1 className="text-2xl font-bold text-gray-900 mb-4">
                Access Denied
              </h1>
              <p className="text-gray-600">
                You don't have permission to access this page.
              </p>
            </div>
          </div>
        );
      }
      
      return <Component {...props} />;
    };
  };
}
