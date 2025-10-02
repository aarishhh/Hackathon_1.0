import React from 'react';
import { Shield } from 'lucide-react';

const LoadingSpinner = ({ size = 'large', message = 'Loading...' }) => {
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8',
    large: 'w-12 h-12'
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="flex justify-center mb-4">
          <Shield className="h-16 w-16 text-primary-600 animate-pulse" />
        </div>
        <div className={`spinner ${sizeClasses[size]} mx-auto mb-4`}></div>
        <p className="text-gray-600 font-medium">{message}</p>
        <p className="text-sm text-gray-500 mt-2">Securing your connection...</p>
      </div>
    </div>
  );
};

export default LoadingSpinner;
