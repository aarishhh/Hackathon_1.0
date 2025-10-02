import React from 'react';
import { Shield, ExternalLink } from 'lucide-react';

const Footer = () => {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-white border-t border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Government Info */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <Shield className="h-6 w-6 text-primary-600" />
              <span className="text-lg font-bold text-gray-900">SecureGov</span>
            </div>
            <p className="text-sm text-gray-600 mb-4">
              A secure digital platform for accessing government services and managing 
              your official documents with the highest standards of data protection and privacy.
            </p>
            <div className="flex items-center space-x-2 text-sm text-gray-500">
              <span>Powered by</span>
              <span className="font-medium text-primary-600">Government of India</span>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-4">
              Quick Links
            </h3>
            <ul className="space-y-2">
              <li>
                <a href="/help" className="text-sm text-gray-600 hover:text-primary-600 transition-colors">
                  Help Center
                </a>
              </li>
              <li>
                <a href="/privacy" className="text-sm text-gray-600 hover:text-primary-600 transition-colors">
                  Privacy Policy
                </a>
              </li>
              <li>
                <a href="/terms" className="text-sm text-gray-600 hover:text-primary-600 transition-colors">
                  Terms of Service
                </a>
              </li>
              <li>
                <a href="/accessibility" className="text-sm text-gray-600 hover:text-primary-600 transition-colors">
                  Accessibility
                </a>
              </li>
            </ul>
          </div>

          {/* Security & Compliance */}
          <div>
            <h3 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-4">
              Security
            </h3>
            <ul className="space-y-2">
              <li className="flex items-center text-sm text-gray-600">
                <Shield className="h-3 w-3 mr-2 text-green-500" />
                SSL Encrypted
              </li>
              <li className="flex items-center text-sm text-gray-600">
                <Shield className="h-3 w-3 mr-2 text-green-500" />
                Data Protected
              </li>
              <li className="flex items-center text-sm text-gray-600">
                <Shield className="h-3 w-3 mr-2 text-green-500" />
                GDPR Compliant
              </li>
              <li>
                <a 
                  href="/security-report" 
                  className="text-sm text-gray-600 hover:text-primary-600 transition-colors flex items-center"
                >
                  Security Report
                  <ExternalLink className="h-3 w-3 ml-1" />
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="mt-8 pt-8 border-t border-gray-200">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="text-sm text-gray-500">
              © {currentYear} Government of India. All rights reserved.
            </div>
            
            <div className="mt-4 md:mt-0 flex items-center space-x-6">
              {/* Government Links */}
              <a
                href="https://www.india.gov.in"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-gray-500 hover:text-primary-600 transition-colors flex items-center"
              >
                India.gov.in
                <ExternalLink className="h-3 w-3 ml-1" />
              </a>
              
              <a
                href="https://digitalindia.gov.in"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-gray-500 hover:text-primary-600 transition-colors flex items-center"
              >
                Digital India
                <ExternalLink className="h-3 w-3 ml-1" />
              </a>
            </div>
          </div>
          
          {/* Disclaimer */}
          <div className="mt-4 text-xs text-gray-400">
            <p>
              This is a secure government portal. Unauthorized access is prohibited and may be subject to legal action.
              All activities are logged and monitored for security purposes.
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
