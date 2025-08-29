import React from 'react';
import { Trophy, TrendingUp, Users, Leaf } from 'lucide-react';

const CommunityLeaderboard = () => {
  const leaders = [
    {
      rank: 1,
      name: 'Kandy Solar Co-op',
      type: 'Community',
      energy: '2,847 kWh',
      members: 45,
      co2Saved: '1.2 tons',
      icon: '🥇'
    },
    {
      rank: 2,
      name: 'Galle Green Network',
      type: 'Community',
      energy: '2,156 kWh',
      members: 32,
      co2Saved: '0.9 tons',
      icon: '🥈'
    },
    {
      rank: 3,
      name: 'Mahinda Rajapaksa',
      type: 'Individual',
      energy: '1,923 kWh',
      members: 1,
      co2Saved: '0.8 tons',
      icon: '🥉'
    },
    {
      rank: 4,
      name: 'Colombo Solar Pool',
      type: 'Pool',
      energy: '1,678 kWh',
      members: 28,
      co2Saved: '0.7 tons',
      icon: '⭐'
    }
  ];

  return (
    <div className="bg-white p-6 rounded-xl shadow-sm">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-gray-900 flex items-center space-x-2">
          <Trophy className="w-5 h-5 text-yellow-600" />
          <span>Community Leaders</span>
        </h2>
        <select className="text-sm border border-gray-300 rounded-md px-3 py-1 focus:outline-none focus:ring-2 focus:ring-orange-500">
          <option>This Month</option>
          <option>Last Month</option>
          <option>All Time</option>
        </select>
      </div>

      <div className="space-y-4">
        {leaders.map((leader) => (
          <div key={leader.rank} className="flex items-center justify-between p-4 border border-gray-100 rounded-lg hover:bg-gray-50 transition-colors">
            <div className="flex items-center space-x-4">
              <div className="text-2xl">{leader.icon}</div>
              
              <div>
                <div className="font-semibold text-gray-900">{leader.name}</div>
                <div className="flex items-center space-x-4 text-sm text-gray-600">
                  <div className="flex items-center space-x-1">
                    <TrendingUp className="w-3 h-3" />
                    <span>{leader.energy}</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <Users className="w-3 h-3" />
                    <span>{leader.members} member{leader.members !== 1 ? 's' : ''}</span>
                  </div>
                  <div className="flex items-center space-x-1">
                    <Leaf className="w-3 h-3" />
                    <span>{leader.co2Saved}</span>
                  </div>
                </div>
              </div>
            </div>

            <div className="text-right">
              <div className="text-lg font-bold text-orange-600">#{leader.rank}</div>
              <div className="text-xs px-2 py-1 rounded-full bg-gray-100 text-gray-700">
                {leader.type}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 p-4 bg-orange-50 rounded-lg">
        <div className="text-center">
          <div className="text-sm text-orange-700 font-medium">Your Rank: #12</div>
          <div className="text-xs text-orange-600">Keep sharing to climb higher! 🚀</div>
        </div>
      </div>
    </div>
  );
};

export default CommunityLeaderboard;