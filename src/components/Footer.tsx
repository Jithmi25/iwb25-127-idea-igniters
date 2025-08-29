import React from 'react';
import { Sun, Facebook, Twitter, Instagram, Mail, Phone, MapPin } from 'lucide-react';

const Footer = () => {
  const isAuthenticated = localStorage.getItem('token');

  // Don't show footer on auth pages
  if (!isAuthenticated) {
    return null;
  }

  return (
    <footer className="bg-gray-900 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Logo and Description */}
          <div className="col-span-1 lg:col-span-2">
            <div className="flex items-center space-x-2 mb-4">
              <div className="bg-gradient-to-r from-orange-400 to-yellow-400 p-2 rounded-lg">
                <Sun className="w-6 h-6 text-white" />
              </div>
              <span className="text-xl font-bold">SolarShare.lk</span>
            </div>
            <p className="text-gray-300 mb-4 max-w-md">
              Sri Lanka's first community-driven renewable energy marketplace. 
              Connecting households, businesses, and communities to share, trade, and invest in solar power.
            </p>
            <div className="flex space-x-4">
              <Facebook className="w-5 h-5 text-gray-400 hover:text-orange-400 cursor-pointer transition-colors" />
              <Twitter className="w-5 h-5 text-gray-400 hover:text-orange-400 cursor-pointer transition-colors" />
              <Instagram className="w-5 h-5 text-gray-400 hover:text-orange-400 cursor-pointer transition-colors" />
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Quick Links</h3>
            <ul className="space-y-2">
              <li><a href="/dashboard" className="text-gray-300 hover:text-orange-400 transition-colors">Dashboard</a></li>
              <li><a href="/trading" className="text-gray-300 hover:text-orange-400 transition-colors">Energy Trading</a></li>
              <li><a href="/community" className="text-gray-300 hover:text-orange-400 transition-colors">Community Pools</a></li>
              <li><a href="/investment" className="text-gray-300 hover:text-orange-400 transition-colors">Investment Hub</a></li>
            </ul>
          </div>

          {/* Contact Info */}
          <div>
            <h3 className="text-lg font-semibold mb-4">Contact</h3>
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <MapPin className="w-4 h-4 text-orange-400" />
                <span className="text-gray-300 text-sm">Colombo, Sri Lanka</span>
              </div>
              <div className="flex items-center space-x-2">
                <Phone className="w-4 h-4 text-orange-400" />
                <span className="text-gray-300 text-sm">+94 11 234 5678</span>
              </div>
              <div className="flex items-center space-x-2">
                <Mail className="w-4 h-4 text-orange-400" />
                <span className="text-gray-300 text-sm">info@solarshare.lk</span>
              </div>
            </div>
          </div>
        </div>

        <div className="border-t border-gray-700 mt-8 pt-8 text-center">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <p className="text-gray-400 text-sm">
              © 2025 SolarShare.lk. All rights reserved.
            </p>
            <div className="flex space-x-6 mt-4 md:mt-0">
              <a href="#" className="text-gray-400 hover:text-orange-400 text-sm transition-colors">Privacy Policy</a>
              <a href="#" className="text-gray-400 hover:text-orange-400 text-sm transition-colors">Terms of Service</a>
              <a href="#" className="text-gray-400 hover:text-orange-400 text-sm transition-colors">Support</a>
            </div>
          </div>
          <p className="text-gray-500 text-xs mt-4">
            Powered by renewable energy • සූර්ය බලශක්තිය • சூரிய சக்தி
          </p>
        </div>
      </div>
    </footer>
  );
};

export default Footer;