import React, { useState } from 'react';
import { User, Settings, Award, TrendingUp, Zap, Leaf, Globe, Bell, Shield, Camera } from 'lucide-react';

const Profile = () => {
  const [activeTab, setActiveTab] = useState('overview');
  const [language, setLanguage] = useState('english');

  const userStats = {
    totalGenerated: '2,847.3 kWh',
    totalEarnings: 'Rs. 85,420',
    co2Saved: '1,423.6 kg',
    ranking: 12,
    joinDate: 'March 2024',
    solarTokens: 2856
  };

  const badges = [
    { name: 'Solar Pioneer', icon: '🏆', earned: true, description: 'First 100 users on SolarShare' },
    { name: 'Green Champion', icon: '🌱', earned: true, description: 'Saved over 1 ton of CO₂' },
    { name: 'Community Leader', icon: '👥', earned: true, description: 'Top trader in your area' },
    { name: 'Eco Warrior', icon: '🛡️', earned: false, description: 'Save 5 tons of CO₂' },
    { name: 'Solar Master', icon: '⚡', earned: false, description: 'Generate 10,000 kWh' },
  ];

  const recentActivity = [
    { type: 'trade', description: 'Sold 15.5 kWh to Nimal Perera', time: '2 hours ago', value: '+Rs. 465' },
    { type: 'achievement', description: 'Earned Green Champion badge', time: '1 day ago', value: '+50 tokens' },
    { type: 'trade', description: 'Bought 8.2 kWh from Solar Pool', time: '2 days ago', value: '-Rs. 246' },
    { type: 'generation', description: 'Generated 25.3 kWh today', time: '3 days ago', value: '+25.3 kWh' }
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Profile Header */}
        <div className="bg-white rounded-xl shadow-sm overflow-hidden mb-8">
          <div className="h-32 bg-gradient-to-r from-orange-400 to-yellow-400"></div>
          <div className="relative px-6 pb-6">
            <div className="flex items-end space-x-4 -mt-16">
              <div className="relative">
                <div className="w-24 h-24 bg-white rounded-full border-4 border-white shadow-lg flex items-center justify-center">
                  <User className="w-12 h-12 text-gray-600" />
                </div>
                <button className="absolute bottom-0 right-0 w-8 h-8 bg-orange-600 rounded-full flex items-center justify-center text-white hover:bg-orange-700 transition-colors">
                  <Camera className="w-4 h-4" />
                </button>
              </div>
              <div className="pb-4">
                <h1 className="text-2xl font-bold text-gray-900">Kasun Perera</h1>
                <p className="text-gray-600">kasun@example.com</p>
                <p className="text-sm text-gray-500">Member since {userStats.joinDate}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-orange-100 rounded-lg">
                <Zap className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">{userStats.totalGenerated}</div>
                <div className="text-sm text-gray-600">Total Generated</div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-green-100 rounded-lg">
                <TrendingUp className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">{userStats.totalEarnings}</div>
                <div className="text-sm text-gray-600">Total Earnings</div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-emerald-100 rounded-lg">
                <Leaf className="w-6 h-6 text-emerald-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">{userStats.co2Saved}</div>
                <div className="text-sm text-gray-600">CO₂ Saved</div>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg mb-8 max-w-lg">
          {['overview', 'badges', 'activity', 'settings'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-2 px-4 rounded-md text-sm font-medium capitalize transition-colors ${
                activeTab === tab
                  ? 'bg-white text-orange-600 shadow-sm'
                  : 'text-gray-600 hover:text-orange-600'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Rankings & Tokens */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6">Community Ranking</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-gradient-to-r from-orange-50 to-yellow-50 rounded-lg">
                  <div>
                    <div className="text-2xl font-bold text-orange-600">#{userStats.ranking}</div>
                    <div className="text-sm text-gray-600">Your Rank in Kandy District</div>
                  </div>
                  <div className="text-4xl">🏆</div>
                </div>
                
                <div className="flex items-center justify-between p-4 bg-green-50 rounded-lg">
                  <div>
                    <div className="text-2xl font-bold text-green-600">{userStats.solarTokens}</div>
                    <div className="text-sm text-gray-600">Solar Tokens</div>
                  </div>
                  <div className="text-4xl">🪙</div>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6">Quick Actions</h3>
              <div className="space-y-3">
                <button className="w-full flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <div className="flex items-center space-x-3">
                    <Zap className="w-5 h-5 text-orange-600" />
                    <span>List Excess Energy</span>
                  </div>
                  <span className="text-gray-400">→</span>
                </button>
                
                <button className="w-full flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <div className="flex items-center space-x-3">
                    <TrendingUp className="w-5 h-5 text-green-600" />
                    <span>View Investment Options</span>
                  </div>
                  <span className="text-gray-400">→</span>
                </button>
                
                <button className="w-full flex items-center justify-between p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <div className="flex items-center space-x-3">
                    <Award className="w-5 h-5 text-purple-600" />
                    <span>Redeem Tokens</span>
                  </div>
                  <span className="text-gray-400">→</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'badges' && (
          <div className="bg-white p-6 rounded-xl shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Achievement Badges</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {badges.map((badge, index) => (
                <div key={index} className={`p-4 rounded-lg border-2 ${
                  badge.earned 
                    ? 'border-orange-200 bg-orange-50' 
                    : 'border-gray-200 bg-gray-50 opacity-60'
                }`}>
                  <div className="text-center">
                    <div className="text-4xl mb-2">{badge.icon}</div>
                    <div className={`font-semibold mb-1 ${
                      badge.earned ? 'text-gray-900' : 'text-gray-500'
                    }`}>
                      {badge.name}
                    </div>
                    <div className="text-sm text-gray-600">
                      {badge.description}
                    </div>
                    {badge.earned && (
                      <div className="mt-2 text-xs bg-orange-100 text-orange-700 px-2 py-1 rounded-full">
                        Earned
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'activity' && (
          <div className="bg-white p-6 rounded-xl shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Recent Activity</h3>
            <div className="space-y-4">
              {recentActivity.map((activity, index) => (
                <div key={index} className="flex items-center justify-between p-4 border border-gray-200 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`p-2 rounded-full ${
                      activity.type === 'trade' ? 'bg-blue-100' :
                      activity.type === 'achievement' ? 'bg-purple-100' :
                      activity.type === 'generation' ? 'bg-orange-100' : 'bg-gray-100'
                    }`}>
                      {activity.type === 'trade' ? <TrendingUp className="w-4 h-4 text-blue-600" /> :
                       activity.type === 'achievement' ? <Award className="w-4 h-4 text-purple-600" /> :
                       activity.type === 'generation' ? <Zap className="w-4 h-4 text-orange-600" /> :
                       <User className="w-4 h-4 text-gray-600" />}
                    </div>
                    <div>
                      <div className="font-medium text-gray-900">{activity.description}</div>
                      <div className="text-sm text-gray-600">{activity.time}</div>
                    </div>
                  </div>
                  <div className={`font-semibold ${
                    activity.value.startsWith('+') ? 'text-green-600' : 
                    activity.value.startsWith('-') ? 'text-red-600' : 'text-gray-900'
                  }`}>
                    {activity.value}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="space-y-6">
            {/* Profile Settings */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center space-x-2">
                <User className="w-5 h-5" />
                <span>Profile Settings</span>
              </h3>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Full Name</label>
                    <input 
                      type="text" 
                      defaultValue="Kasun Perera"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                    <input 
                      type="email" 
                      defaultValue="kasun@example.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Phone</label>
                    <input 
                      type="tel" 
                      defaultValue="+94 77 123 4567"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Location</label>
                    <input 
                      type="text" 
                      defaultValue="Kandy, Sri Lanka"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Language & Preferences */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center space-x-2">
                <Globe className="w-5 h-5" />
                <span>Language & Preferences</span>
              </h3>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Language</label>
                  <select 
                    value={language}
                    onChange={(e) => setLanguage(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  >
                    <option value="english">English</option>
                    <option value="sinhala">සිංහල</option>
                    <option value="tamil">தமிழ்</option>
                  </select>
                </div>
              </div>
            </div>

            {/* Notifications */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center space-x-2">
                <Bell className="w-5 h-5" />
                <span>Notification Settings</span>
              </h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-gray-900">Trade Notifications</div>
                    <div className="text-sm text-gray-600">Get notified about energy trades</div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" defaultChecked />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
                  </label>
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-gray-900">Community Updates</div>
                    <div className="text-sm text-gray-600">Updates from your solar community</div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" defaultChecked />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
                  </label>
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <div className="font-medium text-gray-900">Investment Alerts</div>
                    <div className="text-sm text-gray-600">New investment opportunities</div>
                  </div>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input type="checkbox" className="sr-only peer" />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-orange-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-orange-600"></div>
                  </label>
                </div>
              </div>
            </div>

            {/* Security */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6 flex items-center space-x-2">
                <Shield className="w-5 h-5" />
                <span>Security</span>
              </h3>
              <div className="space-y-3">
                <button className="w-full flex items-center justify-between p-3 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <span>Change Password</span>
                  <span className="text-gray-400">→</span>
                </button>
                <button className="w-full flex items-center justify-between p-3 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                  <span>Enable Two-Factor Authentication</span>
                  <span className="text-gray-400">→</span>
                </button>
              </div>
            </div>

            {/* Save Button */}
            <div className="flex justify-end">
              <button className="bg-orange-600 text-white px-6 py-3 rounded-lg hover:bg-orange-700 transition-colors">
                Save Changes
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Profile;