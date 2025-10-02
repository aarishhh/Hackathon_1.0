import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useAuth } from '../../contexts/AuthContext';
import { 
  Eye, 
  EyeOff, 
  Shield, 
  Lock, 
  User, 
  AlertCircle,
  Smartphone
} from 'lucide-react';
import toast from 'react-hot-toast';

// Validation schema
const loginSchema = yup.object({
  username: yup
    .string()
    .required('Username or email is required')
    .min(3, 'Username must be at least 3 characters'),
  password: yup
    .string()
    .required('Password is required')
    .min(8, 'Password must be at least 8 characters'),
  mfaToken: yup
    .string()
    .when('mfaRequired', {
      is: true,
      then: yup
        .string()
        .required('MFA token is required')
        .matches(/^\d{6}$/, 'MFA token must be 6 digits'),
      otherwise: yup.string()
    })
});

const LoginForm = ({ onSuccess }) => {
  const { login, loginWithMFA, isLoading, error, mfaRequired, clearError } = useAuth();
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    setValue
  } = useForm({
    resolver: yupResolver(loginSchema),
    context: { mfaRequired }
  });

  const onSubmit = async (data) => {
    try {
      clearError();
      
      if (mfaRequired) {
        const result = await loginWithMFA(data.mfaToken);
        if (result.success) {
          onSuccess?.(result.user);
        }
      } else {
        const result = await login({
          username: data.username,
          password: data.password,
          rememberMe
        });
        
        if (result.success && !result.mfaRequired) {
          onSuccess?.(result.user);
        }
      }
    } catch (error) {
      // Error is handled by the auth context
      console.error('Login error:', error);
    }
  };

  const handleMFAResend = () => {
    toast.success('MFA token resent to your authenticator app');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center">
            <Shield className="h-16 w-16 text-primary-600" />
          </div>
          <h2 className="mt-6 text-3xl font-bold text-gray-900">
            {mfaRequired ? 'Multi-Factor Authentication' : 'Secure Login'}
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            {mfaRequired 
              ? 'Enter the 6-digit code from your authenticator app'
              : 'Access your secure government services'
            }
          </p>
          
          {/* Government Badge */}
          <div className="mt-4 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-primary-100 text-primary-800">
            <Shield className="h-3 w-3 mr-1" />
            Government of India
          </div>
        </div>

        {/* Form */}
        <form className="mt-8 space-y-6" onSubmit={handleSubmit(onSubmit)}>
          <div className="space-y-4">
            {!mfaRequired ? (
              <>
                {/* Username Field */}
                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                    Username or Email
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <User className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('username')}
                      type="text"
                      className={`input-field pl-10 ${errors.username ? 'input-error' : ''}`}
                      placeholder="Enter your username or email"
                      autoComplete="username"
                    />
                  </div>
                  {errors.username && (
                    <p className="mt-1 text-sm text-red-600 flex items-center">
                      <AlertCircle className="h-4 w-4 mr-1" />
                      {errors.username.message}
                    </p>
                  )}
                </div>

                {/* Password Field */}
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Lock className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('password')}
                      type={showPassword ? 'text' : 'password'}
                      className={`input-field pl-10 pr-10 ${errors.password ? 'input-error' : ''}`}
                      placeholder="Enter your password"
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? (
                        <EyeOff className="h-5 w-5 text-gray-400" />
                      ) : (
                        <Eye className="h-5 w-5 text-gray-400" />
                      )}
                    </button>
                  </div>
                  {errors.password && (
                    <p className="mt-1 text-sm text-red-600 flex items-center">
                      <AlertCircle className="h-4 w-4 mr-1" />
                      {errors.password.message}
                    </p>
                  )}
                </div>

                {/* Remember Me */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <input
                      id="remember-me"
                      name="remember-me"
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                    />
                    <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
                      Remember me
                    </label>
                  </div>

                  <div className="text-sm">
                    <a href="/forgot-password" className="font-medium text-primary-600 hover:text-primary-500">
                      Forgot your password?
                    </a>
                  </div>
                </div>
              </>
            ) : (
              <>
                {/* MFA Token Field */}
                <div>
                  <label htmlFor="mfaToken" className="block text-sm font-medium text-gray-700 mb-2">
                    Authentication Code
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                      <Smartphone className="h-5 w-5 text-gray-400" />
                    </div>
                    <input
                      {...register('mfaToken')}
                      type="text"
                      className={`input-field pl-10 text-center text-lg tracking-widest ${errors.mfaToken ? 'input-error' : ''}`}
                      placeholder="000000"
                      maxLength={6}
                      autoComplete="one-time-code"
                      autoFocus
                    />
                  </div>
                  {errors.mfaToken && (
                    <p className="mt-1 text-sm text-red-600 flex items-center">
                      <AlertCircle className="h-4 w-4 mr-1" />
                      {errors.mfaToken.message}
                    </p>
                  )}
                </div>

                {/* MFA Help */}
                <div className="text-center">
                  <p className="text-sm text-gray-600 mb-2">
                    Open your authenticator app and enter the 6-digit code
                  </p>
                  <button
                    type="button"
                    onClick={handleMFAResend}
                    className="text-sm text-primary-600 hover:text-primary-500 font-medium"
                  >
                    Didn't receive the code? Try backup code
                  </button>
                </div>
              </>
            )}
          </div>

          {/* Error Display */}
          {error && (
            <div className="alert alert-error">
              <AlertCircle className="h-5 w-5 mr-2" />
              {error}
            </div>
          )}

          {/* Submit Button */}
          <div>
            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary w-full flex justify-center items-center py-3 text-lg"
            >
              {isLoading ? (
                <>
                  <div className="spinner w-5 h-5 mr-2"></div>
                  {mfaRequired ? 'Verifying...' : 'Signing in...'}
                </>
              ) : (
                <>
                  <Lock className="h-5 w-5 mr-2" />
                  {mfaRequired ? 'Verify & Sign In' : 'Sign In Securely'}
                </>
              )}
            </button>
          </div>

          {/* Back to Login */}
          {mfaRequired && (
            <div className="text-center">
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="text-sm text-gray-600 hover:text-gray-800"
              >
                ← Back to login
              </button>
            </div>
          )}
        </form>

        {/* Security Notice */}
        <div className="mt-8 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-start">
            <Shield className="h-5 w-5 text-blue-600 mt-0.5 mr-2" />
            <div className="text-sm text-blue-800">
              <p className="font-medium">Your security is our priority</p>
              <p className="mt-1">
                This is a secure government portal. Your data is encrypted and protected 
                using industry-standard security measures.
              </p>
            </div>
          </div>
        </div>

        {/* Register Link */}
        {!mfaRequired && (
          <div className="text-center">
            <p className="text-sm text-gray-600">
              Don't have an account?{' '}
              <a href="/register" className="font-medium text-primary-600 hover:text-primary-500">
                Register for secure access
              </a>
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoginForm;
