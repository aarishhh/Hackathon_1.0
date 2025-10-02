import React from 'react';
import { useAuth } from '../../contexts/AuthContext';
import {
  Home,
  FileText,
  User,
  Settings,
  Shield,
  Bell,
  HelpCircle,
  Activity,
  Users,
  BarChart3
} from 'lucide-react';

const Sidebar = () => {
  const { user, hasRole } = useAuth();

  const navigation = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: Home,
      current: window.location.pathname === '/dashboard'
    },
    {
      name: 'My Documents',
      href: '/documents',
      icon: FileText,
      current: window.location.pathname === '/documents'
    },
    {
      name: 'Services',
      href: '/services',
      icon: Shield,
      current: window.location.pathname === '/services'
    },
    {
      name: 'Profile',
      href: '/profile',
      icon: User,
      current: window.location.pathname === '/profile'
    },
    {
      name: 'Security',
      href: '/security',
      icon: Settings,
      current: window.location.pathname === '/security'
    },
    {
      name: 'Activity Log',
      href: '/activity',
      icon: Activity,
      current: window.location.pathname === '/activity'
    }
  ];

  const adminNavigation = [
    {
      name: 'User Management',
      href: '/admin/users',
      icon: Users,
      current: window.location.pathname === '/admin/users'
    },
    {
      name: 'System Analytics',
      href: '/admin/analytics',
      icon: BarChart3,
      current: window.location.pathname === '/admin/analytics'
    }
  ];

  const supportNavigation = [
    {
      name: 'Help Center',
      href: '/help',
      icon: HelpCircle
    },
    {
      name: 'Notifications',
      href: '/notifications',
      icon: Bell
    }
  ];

  return (
    <div className="flex flex-col w-64 bg-white border-r border-gray-200 h-screen">
      {/* User Info */}
      <div className="flex items-center px-6 py-4 border-b border-gray-200">
        <div className="h-10 w-10 bg-primary-600 rounded-full flex items-center justify-center">
          <span className="text-white font-medium">
            {user?.personalInfo?.firstName?.[0] || user?.username?.[0]?.toUpperCase()}
          </span>
        </div>
        <div className="ml-3">
          <p className="text-sm font-medium text-gray-900">
            {user?.personalInfo?.firstName} {user?.personalInfo?.lastName}
          </p>
          <p className="text-xs text-gray-500 capitalize">{user?.role}</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-4 py-6 space-y-1 overflow-y-auto">
        {/* Main Navigation */}
        <div className="space-y-1">
          {navigation.map((item) => (
            <a
              key={item.name}
              href={item.href}
              className={`
                group flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors
                ${item.current
                  ? 'bg-primary-100 text-primary-700 border-r-2 border-primary-500'
                  : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                }
              `}
            >
              <item.icon
                className={`
                  mr-3 h-5 w-5 flex-shrink-0
                  ${item.current ? 'text-primary-500' : 'text-gray-400 group-hover:text-gray-500'}
                `}
              />
              {item.name}
            </a>
          ))}
        </div>

        {/* Admin Navigation */}
        {(hasRole('admin') || hasRole('super_admin')) && (
          <div className="pt-6">
            <div className="px-3 pb-2">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
                Administration
              </h3>
            </div>
            <div className="space-y-1">
              {adminNavigation.map((item) => (
                <a
                  key={item.name}
                  href={item.href}
                  className={`
                    group flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors
                    ${item.current
                      ? 'bg-primary-100 text-primary-700 border-r-2 border-primary-500'
                      : 'text-gray-600 hover:bg-gray-50 hover:text-gray-900'
                    }
                  `}
                >
                  <item.icon
                    className={`
                      mr-3 h-5 w-5 flex-shrink-0
                      ${item.current ? 'text-primary-500' : 'text-gray-400 group-hover:text-gray-500'}
                    `}
                  />
                  {item.name}
                </a>
              ))}
            </div>
          </div>
        )}

        {/* Support Navigation */}
        <div className="pt-6">
          <div className="px-3 pb-2">
            <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Support
            </h3>
          </div>
          <div className="space-y-1">
            {supportNavigation.map((item) => (
              <a
                key={item.name}
                href={item.href}
                className="group flex items-center px-3 py-2 text-sm font-medium text-gray-600 rounded-lg hover:bg-gray-50 hover:text-gray-900 transition-colors"
              >
                <item.icon className="mr-3 h-5 w-5 flex-shrink-0 text-gray-400 group-hover:text-gray-500" />
                {item.name}
              </a>
            ))}
          </div>
        </div>
      </nav>

      {/* Footer */}
      <div className="px-4 py-4 border-t border-gray-200">
        <div className="text-xs text-gray-500 text-center">
          <p>SecureGov v1.0</p>
          <p className="mt-1">Government of India</p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
