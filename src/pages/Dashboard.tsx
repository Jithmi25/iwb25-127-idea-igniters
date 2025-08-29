import React, { useState } from 'react';
import { Sun, Zap, DollarSign, Leaf, TrendingUp, Award, Users, Battery } from 'lucide-react';
import EnergyChart from '../components/EnergyChart';
import RecentTransactions from '../components/RecentTransactions';
import CommunityLeaderboard from '../components/CommunityLeaderboard';

const Dashboard = () => {
  const [selectedPeriod, setSelectedPeriod] = useState('week');

  const stats = [
    {
      icon: <Sun className="w-6 h-6 text-orange-600" />,
      title: 'Energy Generated',
      value: '145.2 kWh',
      change: '+12%',
      color: 'orange'
    },
    {
      icon: <Zap className="w-6 h-6 text-blue-600" />,
      title: 'Energy Consumed',
      value: '98.7 kWh',
      change: '-5%',
      color: 'blue'
    },
    {
      icon: <DollarSign className="w-6 h-6 text-green-600" />,
      title: 'Earnings',
      value: 'Rs. 2,847',
      change: '+18%',
      color: 'green'
    },
    {
      icon: <Leaf className="w-6 h-6 text-emerald-600" />,
      title: 'CO₂ Saved',
      value: '87.3 kg',
      change: '+15%',
      color: 'emerald'
    }
  ];

  const badges = [
    { name: 'Solar Pioneer', icon: '🏆', description: 'First 100 users' },
    { name: 'Green Champion', icon: '🌱', description: '1 ton CO₂ saved' },
    { name: 'Community Leader', icon: '👥', description: 'Top trader in area' }
  ];

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Welcome back, Kasun! 🌞
          </h1>
          <p className="text-gray-600">
            Here's your solar energy overview for today
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {stats.map((stat, index) => (
            <div key={index} className="bg-white p-6 rounded-xl shadow-sm hover:shadow-md transition-shadow">
              <div className="flex items-center justify-between mb-4">
                <div className={`p-3 rounded-lg bg-${stat.color}-100`}>
                  {stat.icon}
                </div>
                <span className={`text-sm font-medium px-2 py-1 rounded-full ${
                  stat.change.startsWith('+') 
                    ? 'text-green-700 bg-green-100' 
                    : 'text-red-700 bg-red-100'
                }`}>
                  {stat.change}
                </span>
              </div>
              <h3 className="text-2xl font-bold text-gray-900 mb-1">{stat.value}</h3>
              <p className="text-gray-600 text-sm">{stat.title}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          {/* Energy Chart */}
          <div className="lg:col-span-2">
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-semibold text-gray-900">Energy Flow</h2>
                <div className="flex space-x-2">
                  {['day', 'week', 'month'].map((period) => (
                    <button
                      key={period}
                      onClick={() => setSelectedPeriod(period)}
                      className={`px-3 py-1 rounded-md text-sm font-medium capitalize ${
                        selectedPeriod === period
                          ? 'bg-orange-100 text-orange-700'
                          : 'text-gray-600 hover:text-orange-600'
                      }`}
                    >
                      {period}
                    </button>
                  ))}
                </div>
              </div>
              <EnergyChart period={selectedPeriod} />
            </div>
          </div>

          {/* Quick Actions */}
          <div className="space-y-6">
            {/* Solar Status */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Solar Status</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Battery className="w-5 h-5 text-green-600" />
                    <span className="text-sm text-gray-600">Battery</span>
                  </div>
                  <span className="text-sm font-medium text-green-700">85% Full</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div className="bg-green-500 h-2 rounded-full" style={{ width: '85%' }}></div>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Sun className="w-5 h-5 text-orange-600" />
                    <span className="text-sm text-gray-600">Generation</span>
                  </div>
                  <span className="text-sm font-medium text-orange-700">2.3 kW</span>
                </div>
              </div>
            </div>

            {/* Badges */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Your Badges</h3>
              <div className="space-y-3">
                {badges.map((badge, index) => (
                  <div key={index} className="flex items-center space-x-3 p-2 rounded-lg hover:bg-gray-50">
                    <span className="text-2xl">{badge.icon}</span>
                    <div>
                      <div className="font-medium text-gray-900">{badge.name}</div>
                      <div className="text-sm text-gray-600">{badge.description}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Transactions */}
          <RecentTransactions />
          
          {/* Community Leaderboard */}
          <CommunityLeaderboard />
        </div>
      </div>
    </div>
  );
};

export default Dashboard;