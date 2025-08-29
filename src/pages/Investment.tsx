import React, { useState } from 'react';
import { TrendingUp, DollarSign, Calendar, Users, Star, Shield, ChevronRight, PieChart } from 'lucide-react';

const Investment = () => {
  const [selectedCategory, setSelectedCategory] = useState('all');

  const investmentOpportunities = [
    {
      id: 1,
      title: 'Kandy Regional Solar Grid',
      type: 'Infrastructure',
      minInvestment: 'Rs. 100,000',
      expectedReturn: '14.2%',
      duration: '5 years',
      riskLevel: 'Low',
      funded: 78,
      totalRequired: 'Rs. 50M',
      investors: 234,
      image: 'https://images.pexels.com/photos/2800832/pexels-photo-2800832.jpeg?auto=compress&cs=tinysrgb&w=400',
      description: 'Large-scale solar infrastructure connecting 15 communities in Kandy district.'
    },
    {
      id: 2,
      title: 'Rural Solar Microloan Fund',
      type: 'Social Impact',
      minInvestment: 'Rs. 25,000',
      expectedReturn: '9.8%',
      duration: '3 years',
      riskLevel: 'Medium',
      funded: 65,
      totalRequired: 'Rs. 20M',
      investors: 156,
      image: 'https://images.pexels.com/photos/547114/pexels-photo-547114.jpeg?auto=compress&cs=tinysrgb&w=400',
      description: 'Help rural families install solar systems through microfinancing.'
    },
    {
      id: 3,
      title: 'Colombo Rooftop Solar Network',
      type: 'Urban Development',
      minInvestment: 'Rs. 75,000',
      expectedReturn: '12.5%',
      duration: '4 years',
      riskLevel: 'Low',
      funded: 42,
      totalRequired: 'Rs. 35M',
      investors: 89,
      image: 'https://images.pexels.com/photos/9875474/pexels-photo-9875474.jpeg?auto=compress&cs=tinysrgb&w=400',
      description: 'Urban solar deployment across commercial buildings in Colombo.'
    },
    {
      id: 4,
      title: 'Agri-Solar Innovation Project',
      type: 'Agriculture',
      minInvestment: 'Rs. 50,000',
      expectedReturn: '11.9%',
      duration: '6 years',
      riskLevel: 'Medium',
      funded: 38,
      totalRequired: 'Rs. 25M',
      investors: 67,
      image: 'https://images.pexels.com/photos/1459337/pexels-photo-1459337.jpeg?auto=compress&cs=tinysrgb&w=400',
      description: 'Combining agriculture with solar panels for maximum land efficiency.'
    }
  ];

  const myInvestments = [
    {
      project: 'Galle Solar Farm',
      invested: 'Rs. 150,000',
      currentValue: 'Rs. 167,500',
      return: '+11.7%',
      status: 'Active'
    },
    {
      project: 'Jaffna Community Pool',
      invested: 'Rs. 75,000',
      currentValue: 'Rs. 81,250',
      return: '+8.3%',
      status: 'Active'
    }
  ];

  const categories = [
    { id: 'all', label: 'All Projects' },
    { id: 'infrastructure', label: 'Infrastructure' },
    { id: 'social', label: 'Social Impact' },
    { id: 'urban', label: 'Urban Development' },
    { id: 'agriculture', label: 'Agriculture' }
  ];

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Low': return 'text-green-600 bg-green-100';
      case 'Medium': return 'text-yellow-600 bg-yellow-100';
      case 'High': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Investment Hub 📈
          </h1>
          <p className="text-gray-600">
            Invest in Sri Lanka's renewable energy future and earn sustainable returns
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-green-100 rounded-lg">
                <DollarSign className="w-6 h-6 text-green-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">Rs. 245M</div>
                <div className="text-sm text-gray-600">Total Invested</div>
              </div>
            </div>
          </div>
          
          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-blue-100 rounded-lg">
                <TrendingUp className="w-6 h-6 text-blue-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">12.3%</div>
                <div className="text-sm text-gray-600">Avg. Returns</div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-orange-100 rounded-lg">
                <Users className="w-6 h-6 text-orange-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">1,847</div>
                <div className="text-sm text-gray-600">Active Investors</div>
              </div>
            </div>
          </div>

          <div className="bg-white p-6 rounded-xl shadow-sm">
            <div className="flex items-center space-x-3">
              <div className="p-3 bg-purple-100 rounded-lg">
                <PieChart className="w-6 h-6 text-purple-600" />
              </div>
              <div>
                <div className="text-2xl font-bold text-gray-900">43</div>
                <div className="text-sm text-gray-600">Active Projects</div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Investment Section */}
          <div className="lg:col-span-2">
            {/* Category Filter */}
            <div className="flex flex-wrap gap-2 mb-6">
              {categories.map((category) => (
                <button
                  key={category.id}
                  onClick={() => setSelectedCategory(category.id)}
                  className={`px-4 py-2 rounded-full text-sm font-medium transition-colors ${
                    selectedCategory === category.id
                      ? 'bg-orange-600 text-white'
                      : 'bg-white text-gray-600 hover:bg-orange-50 hover:text-orange-600'
                  }`}
                >
                  {category.label}
                </button>
              ))}
            </div>

            {/* Investment Opportunities */}
            <div className="space-y-6">
              {investmentOpportunities.map((opportunity) => (
                <div key={opportunity.id} className="bg-white p-6 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                  <div className="flex flex-col md:flex-row md:items-start space-y-4 md:space-y-0 md:space-x-6">
                    <img 
                      src={opportunity.image} 
                      alt={opportunity.title}
                      className="w-full md:w-32 h-32 object-cover rounded-lg"
                    />
                    
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h3 className="text-xl font-semibold text-gray-900 mb-1">
                            {opportunity.title}
                          </h3>
                          <div className="flex items-center space-x-2 mb-2">
                            <span className="text-sm px-2 py-1 bg-orange-100 text-orange-700 rounded-full">
                              {opportunity.type}
                            </span>
                            <span className={`text-sm px-2 py-1 rounded-full ${getRiskColor(opportunity.riskLevel)}`}>
                              {opportunity.riskLevel} Risk
                            </span>
                          </div>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-bold text-green-600">{opportunity.expectedReturn}</div>
                          <div className="text-sm text-gray-600">Expected Return</div>
                        </div>
                      </div>

                      <p className="text-gray-600 mb-4">{opportunity.description}</p>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                        <div>
                          <div className="text-sm text-gray-600">Min. Investment</div>
                          <div className="font-semibold text-gray-900">{opportunity.minInvestment}</div>
                        </div>
                        <div>
                          <div className="text-sm text-gray-600">Duration</div>
                          <div className="font-semibold text-gray-900">{opportunity.duration}</div>
                        </div>
                        <div>
                          <div className="text-sm text-gray-600">Target</div>
                          <div className="font-semibold text-gray-900">{opportunity.totalRequired}</div>
                        </div>
                        <div>
                          <div className="text-sm text-gray-600">Investors</div>
                          <div className="font-semibold text-gray-900">{opportunity.investors}</div>
                        </div>
                      </div>

                      <div className="mb-4">
                        <div className="flex items-center justify-between text-sm mb-2">
                          <span className="text-gray-600">Funding Progress</span>
                          <span className="font-medium">{opportunity.funded}% funded</span>
                        </div>
                        <div className="w-full bg-gray-200 rounded-full h-2">
                          <div 
                            className="bg-orange-500 h-2 rounded-full" 
                            style={{ width: `${opportunity.funded}%` }}
                          ></div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <Shield className="w-4 h-4 text-green-500" />
                          <span className="text-sm text-gray-600">SEC Registered</span>
                        </div>
                        <div className="flex space-x-3">
                          <button 
                            onClick={() => handleLearnMore(opportunity.id)}
                            className="text-orange-600 hover:text-orange-700 font-medium"
                          >
                            Learn More
                          </button>
                          <button 
                            onClick={() => handleInvestNow(opportunity.id)}
                            className="bg-orange-600 text-white px-6 py-2 rounded-lg hover:bg-orange-700 transition-colors flex items-center space-x-2"
                          >
                            <span>Invest Now</span>
                            <ChevronRight className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* My Investments */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
                <PieChart className="w-5 h-5 text-orange-600" />
                <span>My Investments</span>
              </h3>
              
              {myInvestments.length > 0 ? (
                <div className="space-y-4">
                  {myInvestments.map((investment, index) => (
                    <div key={index} className="border border-gray-200 p-4 rounded-lg">
                      <div className="font-medium text-gray-900 mb-2">{investment.project}</div>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <div className="text-gray-600">Invested</div>
                          <div className="font-semibold">{investment.invested}</div>
                        </div>
                        <div>
                          <div className="text-gray-600">Current Value</div>
                          <div className="font-semibold text-green-600">{investment.currentValue}</div>
                        </div>
                        <div>
                          <div className="text-gray-600">Return</div>
                          <div className="font-semibold text-green-600">{investment.return}</div>
                        </div>
                        <div>
                          <div className="text-gray-600">Status</div>
                          <div className="font-semibold text-blue-600">{investment.status}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-6 text-gray-600">
                  <div className="mb-2">No investments yet</div>
                  <button className="text-orange-600 hover:text-orange-700 font-medium">
                    Make your first investment →
                  </button>
                </div>
              )}
            </div>

            {/* Investment Tips */}
            <div className="bg-gradient-to-br from-orange-50 to-yellow-50 p-6 rounded-xl border border-orange-100">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
                <Star className="w-5 h-5 text-orange-600" />
                <span>Investment Tips</span>
              </h3>
              <div className="space-y-3 text-sm">
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-gray-700">Diversify across multiple projects to reduce risk</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-gray-700">Consider your investment timeline and goals</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-gray-700">Review project documentation carefully</span>
                </div>
                <div className="flex items-start space-x-2">
                  <div className="w-2 h-2 bg-orange-400 rounded-full mt-2"></div>
                  <span className="text-gray-700">Start with smaller amounts as you learn</span>
                </div>
              </div>
            </div>

            {/* Risk Disclaimer */}
            <div className="bg-gray-50 p-4 rounded-lg border">
              <div className="flex items-center space-x-2 mb-2">
                <Shield className="w-4 h-4 text-gray-600" />
                <span className="text-sm font-medium text-gray-900">Risk Disclaimer</span>
              </div>
              <p className="text-xs text-gray-600">
                All investments carry risk. Past performance does not guarantee future results. 
                Please read all terms and conditions before investing.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Investment;