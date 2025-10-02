import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import {
  Shield,
  FileText,
  User,
  Bell,
  Activity,
  CheckCircle,
  AlertTriangle,
  Clock,
  Download,
  Upload,
  Settings,
  Lock,
  Eye,
  TrendingUp
} from 'lucide-react';

const Dashboard = () => {
  const { user, getSecurityLevel } = useAuth();
  const [stats, setStats] = useState({
    documentsCount: 0,
    pendingRequests: 0,
    securityScore: 0,
    lastLogin: null
  });

  const securityLevel = getSecurityLevel();

  useEffect(() => {
    // Simulate loading dashboard data
    const loadDashboardData = () => {
      setStats({
        documentsCount: 12,
        pendingRequests: 3,
        securityScore: securityLevel === 'high' ? 95 : securityLevel === 'medium' ? 75 : 45,
        lastLogin: user?.security?.lastLogin
      });
    };

    loadDashboardData();
  }, [user, securityLevel]);

  const securityLevelConfig = {
    high: {
      color: 'text-green-600',
      bgColor: 'bg-green-50',
      borderColor: 'border-green-200',
      icon: CheckCircle,
      message: 'Your account is highly secure'
    },
    medium: {
      color: 'text-yellow-600',
      bgColor: 'bg-yellow-50',
      borderColor: 'border-yellow-200',
      icon: AlertTriangle,
      message: 'Consider enabling additional security features'
    },
    low: {
      color: 'text-red-600',
      bgColor: 'bg-red-50',
      borderColor: 'border-red-200',
      icon: AlertTriangle,
      message: 'Your account needs security improvements'
    }
  };

  const SecurityIcon = securityLevelConfig[securityLevel].icon;

  const quickActions = [
    {
      title: 'View Documents',
      description: 'Access your government documents',
      icon: FileText,
      href: '/documents',
      color: 'text-blue-600 bg-blue-50 hover:bg-blue-100'
    },
    {
      title: 'Submit Request',
      description: 'Apply for government services',
      icon: Upload,
      href: '/services',
      color: 'text-green-600 bg-green-50 hover:bg-green-100'
    },
    {
      title: 'Profile Settings',
      description: 'Update your personal information',
      icon: User,
      href: '/profile',
      color: 'text-purple-600 bg-purple-50 hover:bg-purple-100'
    },
    {
      title: 'Security Settings',
      description: 'Manage your account security',
      icon: Lock,
      href: '/security',
      color: 'text-red-600 bg-red-50 hover:bg-red-100'
    }
  ];

  const recentActivities = [
    {
      id: 1,
      action: 'Document downloaded',
      description: 'Aadhaar Card (PDF)',
      timestamp: '2 hours ago',
      icon: Download,
      color: 'text-blue-600'
    },
    {
      id: 2,
      action: 'Profile updated',
      description: 'Contact information changed',
      timestamp: '1 day ago',
      icon: User,
      color: 'text-green-600'
    },
    {
      id: 3,
      action: 'Security login',
      description: 'Successful login from new device',
      timestamp: '3 days ago',
      icon: Shield,
      color: 'text-yellow-600'
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      {/* Welcome Section */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">
          Welcome back, {user?.personalInfo?.firstName || user?.username}
        </h1>
        <p className="mt-2 text-gray-600">
          Here's your secure government services dashboard
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Documents Count */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="p-3 rounded-lg bg-blue-50">
                <FileText className="h-6 w-6 text-blue-600" />
              </div>
              <div className="ml-4">
                <p className="text-2xl font-bold text-gray-900">{stats.documentsCount}</p>
                <p className="text-sm text-gray-600">Documents</p>
              </div>
            </div>
          </div>
        </div>

        {/* Pending Requests */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="p-3 rounded-lg bg-yellow-50">
                <Clock className="h-6 w-6 text-yellow-600" />
              </div>
              <div className="ml-4">
                <p className="text-2xl font-bold text-gray-900">{stats.pendingRequests}</p>
                <p className="text-sm text-gray-600">Pending</p>
              </div>
            </div>
          </div>
        </div>

        {/* Security Score */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className={`p-3 rounded-lg ${securityLevelConfig[securityLevel].bgColor}`}>
                <Shield className={`h-6 w-6 ${securityLevelConfig[securityLevel].color}`} />
              </div>
              <div className="ml-4">
                <p className="text-2xl font-bold text-gray-900">{stats.securityScore}%</p>
                <p className="text-sm text-gray-600">Security</p>
              </div>
            </div>
          </div>
        </div>

        {/* Account Status */}
        <div className="card">
          <div className="card-body">
            <div className="flex items-center">
              <div className="p-3 rounded-lg bg-green-50">
                <CheckCircle className="h-6 w-6 text-green-600" />
              </div>
              <div className="ml-4">
                <p className="text-2xl font-bold text-green-600">Active</p>
                <p className="text-sm text-gray-600">Status</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-8">
          {/* Security Status */}
          <div className={`card ${securityLevelConfig[securityLevel].borderColor} border-l-4`}>
            <div className="card-header">
              <div className="flex items-center">
                <SecurityIcon className={`h-6 w-6 mr-3 ${securityLevelConfig[securityLevel].color}`} />
                <h2 className="text-lg font-semibold text-gray-900">
                  Security Status: {securityLevel.toUpperCase()}
                </h2>
              </div>
            </div>
            <div className="card-body">
              <p className="text-gray-600 mb-4">
                {securityLevelConfig[securityLevel].message}
              </p>
              
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Two-Factor Authentication</span>
                  <span className={`text-sm font-medium ${user?.mfa?.enabled ? 'text-green-600' : 'text-red-600'}`}>
                    {user?.mfa?.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Email Verification</span>
                  <span className={`text-sm font-medium ${user?.emailVerified ? 'text-green-600' : 'text-red-600'}`}>
                    {user?.emailVerified ? 'Verified' : 'Pending'}
                  </span>
                </div>
                
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-600">Phone Verification</span>
                  <span className={`text-sm font-medium ${user?.phoneVerified ? 'text-green-600' : 'text-red-600'}`}>
                    {user?.phoneVerified ? 'Verified' : 'Pending'}
                  </span>
                </div>
              </div>

              {securityLevel !== 'high' && (
                <div className="mt-4">
                  <a
                    href="/security"
                    className="btn-primary inline-flex items-center"
                  >
                    <Settings className="h-4 w-4 mr-2" />
                    Improve Security
                  </a>
                </div>
              )}
            </div>
          </div>

          {/* Quick Actions */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Quick Actions</h2>
            </div>
            <div className="card-body">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {quickActions.map((action, index) => (
                  <a
                    key={index}
                    href={action.href}
                    className={`p-4 rounded-lg border border-gray-200 hover:border-gray-300 transition-all duration-200 ${action.color}`}
                  >
                    <div className="flex items-center">
                      <action.icon className="h-6 w-6 mr-3" />
                      <div>
                        <h3 className="font-medium text-gray-900">{action.title}</h3>
                        <p className="text-sm text-gray-600">{action.description}</p>
                      </div>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-8">
          {/* Recent Activity */}
          <div className="card">
            <div className="card-header">
              <div className="flex items-center">
                <Activity className="h-5 w-5 mr-2 text-gray-600" />
                <h2 className="text-lg font-semibold text-gray-900">Recent Activity</h2>
              </div>
            </div>
            <div className="card-body">
              <div className="space-y-4">
                {recentActivities.map((activity) => (
                  <div key={activity.id} className="flex items-start space-x-3">
                    <div className={`p-2 rounded-lg bg-gray-50`}>
                      <activity.icon className={`h-4 w-4 ${activity.color}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-gray-900">
                        {activity.action}
                      </p>
                      <p className="text-sm text-gray-600">
                        {activity.description}
                      </p>
                      <p className="text-xs text-gray-500 mt-1">
                        {activity.timestamp}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="card-footer">
              <a
                href="/activity"
                className="text-sm text-primary-600 hover:text-primary-700 font-medium flex items-center"
              >
                <Eye className="h-4 w-4 mr-1" />
                View all activity
              </a>
            </div>
          </div>

          {/* Account Information */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Account Information</h2>
            </div>
            <div className="card-body">
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-gray-600">Account Type</label>
                  <p className="text-sm text-gray-900 capitalize">{user?.role}</p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-600">Member Since</label>
                  <p className="text-sm text-gray-900">
                    {user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : 'N/A'}
                  </p>
                </div>
                
                <div>
                  <label className="text-sm font-medium text-gray-600">Last Login</label>
                  <p className="text-sm text-gray-900">
                    {user?.security?.lastLogin 
                      ? new Date(user.security.lastLogin).toLocaleDateString()
                      : 'N/A'
                    }
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Help & Support */}
          <div className="card">
            <div className="card-header">
              <h2 className="text-lg font-semibold text-gray-900">Help & Support</h2>
            </div>
            <div className="card-body">
              <div className="space-y-3">
                <a
                  href="/help"
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  User Guide
                </a>
                <a
                  href="/support"
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  Contact Support
                </a>
                <a
                  href="/faq"
                  className="block text-sm text-primary-600 hover:text-primary-700"
                >
                  Frequently Asked Questions
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
