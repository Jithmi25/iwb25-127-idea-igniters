import React, { useState } from 'react';
import { Search, Filter, Zap, MapPin, Clock, User, Star } from 'lucide-react';

const Trading = () => {
  const [activeTab, setActiveTab] = useState('buy');
  const [searchTerm, setSearchTerm] = useState('');

  const availableEnergy = [
    {
      id: 1,
      seller: 'Saman Perera',
      location: 'Kandy',
      amount: '45.2 kWh',
      price: 'Rs. 28/kWh',
      total: 'Rs. 1,266',
      distance: '2.3 km',
      rating: 4.8,
      type: 'Rooftop Solar',
      timeLeft: '2h 15m',
      renewable: true
    },
    {
      id: 2,
      seller: 'Green Valley Farm',
      location: 'Gampaha',
      amount: '120.5 kWh',
      price: 'Rs. 26/kWh',
      total: 'Rs. 3,133',
      distance: '5.7 km',
      rating: 4.9,
      type: 'Agri-Solar',
      timeLeft: '4h 32m',
      renewable: true
    },
    {
      id: 3,
      seller: 'Colombo Solar Pool',
      location: 'Colombo 07',
      amount: '78.9 kWh',
      price: 'Rs. 30/kWh',
      total: 'Rs. 2,367',
      distance: '8.1 km',
      rating: 4.7,
      type: 'Community Pool',
      timeLeft: '6h 45m',
      renewable: true
    },
    {
      id: 4,
      seller: 'Nimal Silva',
      location: 'Mt. Lavinia',
      amount: '32.6 kWh',
      price: 'Rs. 29/kWh',
      total: 'Rs. 945',
      distance: '12.4 km',
      rating: 4.6,
      type: 'Rooftop Solar',
      timeLeft: '1h 20m',
      renewable: true
    }
  ];

  const myListings = [
    {
      id: 1,
      amount: '35.8 kWh',
      price: 'Rs. 27/kWh',
      total: 'Rs. 967',
      bids: 3,
      highestBid: 'Rs. 28/kWh',
      timeLeft: '5h 12m',
      status: 'active'
    },
    {
      id: 2,
      amount: '52.1 kWh',
      price: 'Rs. 25/kWh',
      total: 'Rs. 1,303',
      bids: 7,
      highestBid: 'Rs. 26/kWh',
      timeLeft: '2h 45m',
      status: 'active'
    }
  ];

  const handleBuyEnergy = (listingId: number) => {
    const listing = availableEnergy.find(l => l.id === listingId);
    if (listing) {
      const confirmed = window.confirm(
        `Purchase ${listing.amount} from ${listing.seller} for ${listing.total}?\n\nThis will initiate a secure energy transfer.`
      );
      if (confirmed) {
        alert(`✅ Purchase initiated!\n\nEnergy: ${listing.amount}\nSeller: ${listing.seller}\nTotal: ${listing.total}\n\nTransaction ID: TXN${Date.now()}`);
      }
    }
  };

  const handleListEnergy = () => {
    const amount = prompt('Enter energy amount to list (kWh):');
    const price = prompt('Enter price per kWh (Rs.):');
    
    if (amount && price) {
      const total = (parseFloat(amount) * parseFloat(price)).toFixed(0);
      alert(`✅ Energy listed successfully!\n\nAmount: ${amount} kWh\nPrice: Rs. ${price}/kWh\nTotal Value: Rs. ${total}\n\nListing ID: LST${Date.now()}`);
    }
  };

  const handleEditListing = (listingId: number) => {
    const listing = myListings.find(l => l.id === listingId);
    if (listing) {
      const newPrice = prompt(`Edit price for ${listing.amount}:`, listing.price.replace('Rs. ', '').replace('/kWh', ''));
      if (newPrice) {
        alert(`✅ Listing updated!\n\nNew price: Rs. ${newPrice}/kWh\nListing ID: ${listingId}`);
      }
    }
  };

  const handleCancelListing = (listingId: number) => {
    const listing = myListings.find(l => l.id === listingId);
    if (listing) {
      const confirmed = window.confirm(`Cancel listing for ${listing.amount}?`);
      if (confirmed) {
        alert(`✅ Listing cancelled!\n\nListing ID: ${listingId}`);
      }
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Energy Trading Marketplace
          </h1>
          <p className="text-gray-600">
            Buy and sell renewable energy directly with your community
          </p>
        </div>

        {/* Tabs */}
        <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg mb-8 max-w-md">
          <button
            onClick={() => setActiveTab('buy')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'buy'
                ? 'bg-white text-orange-600 shadow-sm'
                : 'text-gray-600 hover:text-orange-600'
            }`}
          >
            Buy Energy ⚡
          </button>
          <button
            onClick={() => setActiveTab('sell')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'sell'
                ? 'bg-white text-orange-600 shadow-sm'
                : 'text-gray-600 hover:text-orange-600'
            }`}
          >
            My Listings 📊
          </button>
        </div>

        {activeTab === 'buy' && (
          <div>
            {/* Search and Filters */}
            <div className="bg-white p-6 rounded-xl shadow-sm mb-8">
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
                  <input
                    type="text"
                    placeholder="Search by location or seller..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-orange-500"
                  />
                </div>
                <div className="flex space-x-2">
                  <select className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500">
                    <option>All Types</option>
                    <option>Rooftop Solar</option>
                    <option>Community Pool</option>
                    <option>Agri-Solar</option>
                  </select>
                  <select className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500">
                    <option>Price: Low to High</option>
                    <option>Price: High to Low</option>
                    <option>Distance: Nearest</option>
                    <option>Amount: Largest</option>
                  </select>
                  <button className="px-4 py-3 bg-orange-600 text-white rounded-lg hover:bg-orange-700 flex items-center space-x-2">
                    <Filter className="w-4 h-4" />
                    <span>Filter</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Available Energy Listings */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {availableEnergy.map((listing) => (
                <div key={listing.id} className="bg-white p-6 rounded-xl shadow-sm hover:shadow-md transition-shadow">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center">
                        <User className="w-6 h-6 text-orange-600" />
                      </div>
                      <div>
                        <h3 className="font-semibold text-gray-900">{listing.seller}</h3>
                        <div className="flex items-center space-x-2 text-sm text-gray-600">
                          <MapPin className="w-4 h-4" />
                          <span>{listing.location}</span>
                          <span>•</span>
                          <span>{listing.distance}</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Star className="w-4 h-4 text-yellow-400 fill-current" />
                      <span className="text-sm font-medium">{listing.rating}</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div>
                      <div className="text-2xl font-bold text-gray-900">{listing.amount}</div>
                      <div className="text-sm text-gray-600">Available Energy</div>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-orange-600">{listing.price}</div>
                      <div className="text-sm text-gray-600">Price per kWh</div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center space-x-4">
                      <div className="flex items-center space-x-1">
                        <Zap className="w-4 h-4 text-green-500" />
                        <span className="text-sm text-gray-600">{listing.type}</span>
                      </div>
                      <div className="flex items-center space-x-1">
                        <Clock className="w-4 h-4 text-gray-400" />
                        <span className="text-sm text-gray-600">{listing.timeLeft}</span>
                      </div>
                    </div>
                    {listing.renewable && (
                      <div className="bg-green-100 text-green-700 text-xs px-2 py-1 rounded-full">
                        100% Renewable
                      </div>
                    )}
                  </div>

                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-lg font-semibold text-gray-900">Total: {listing.total}</div>
                    </div>
                    <button 
                      onClick={() => handleBuyEnergy(listing.id)}
                      className="bg-orange-600 text-white px-6 py-2 rounded-lg hover:bg-orange-700 transition-colors"
                    >
                      Buy Now
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'sell' && (
          <div className="space-y-6">
            {/* Create New Listing */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Create New Listing</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <input
                  type="number"
                  placeholder="Energy amount (kWh)"
                  className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500"
                />
                <input
                  type="number"
                  placeholder="Price per kWh (Rs.)"
                  className="px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-orange-500"
                />
                <button 
                  onClick={handleListEnergy}
                  className="bg-orange-600 text-white px-6 py-3 rounded-lg hover:bg-orange-700 transition-colors"
                >
                  List Energy
                </button>
              </div>
            </div>

            {/* My Active Listings */}
            <div className="bg-white p-6 rounded-xl shadow-sm">
              <h3 className="text-lg font-semibold text-gray-900 mb-6">My Active Listings</h3>
              <div className="space-y-4">
                {myListings.map((listing) => (
                  <div key={listing.id} className="border border-gray-200 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-4">
                        <div>
                          <div className="font-semibold text-gray-900">{listing.amount}</div>
                          <div className="text-sm text-gray-600">at {listing.price}</div>
                        </div>
                        <div className="text-right">
                          <div className="font-semibold text-orange-600">{listing.total}</div>
                          <div className="text-sm text-gray-600">Total Value</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <div className="text-sm text-gray-900">{listing.bids} bids</div>
                        <div className="text-sm text-green-600">Highest: {listing.highestBid}</div>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-1 text-sm text-gray-600">
                        <Clock className="w-4 h-4" />
                        <span>{listing.timeLeft} remaining</span>
                      </div>
                      <div className="space-x-2">
                        <button 
                          onClick={() => handleEditListing(listing.id)}
                          className="text-orange-600 hover:text-orange-700 text-sm font-medium"
                        >
                          Edit
                        </button>
                        <button 
                          onClick={() => handleCancelListing(listing.id)}
                          className="text-red-600 hover:text-red-700 text-sm font-medium"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Trading;