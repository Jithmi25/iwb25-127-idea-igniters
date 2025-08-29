import React from 'react';
import { ArrowUpRight, ArrowDownLeft, Clock } from 'lucide-react';

const RecentTransactions = () => {
  const transactions = [
    {
      id: 1,
      type: 'sell',
      amount: '15.5 kWh',
      price: 'Rs. 465',
      buyer: 'Nimal Perera',
      time: '2 hours ago',
      status: 'completed'
    },
    {
      id: 2,
      type: 'buy',
      amount: '8.2 kWh',
      price: 'Rs. 246',
      seller: 'Colombo Solar Pool',
      time: '5 hours ago',
      status: 'completed'
    },
    {
      id: 3,
      type: 'sell',
      amount: '22.1 kWh',
      price: 'Rs. 663',
      buyer: 'Gampaha Community',
      time: '1 day ago',
      status: 'pending'
    },
    {
      id: 4,
      type: 'sell',
      amount: '12.8 kWh',
      price: 'Rs. 384',
      buyer: 'Saman Silva',
      time: '2 days ago',
      status: 'completed'
    }
  ];

  return (
    <div className="bg-white p-6 rounded-xl shadow-sm">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-gray-900">Recent Transactions</h2>
        <button className="text-orange-600 hover:text-orange-700 text-sm font-medium">
          View all
        </button>
      </div>

      <div className="space-y-4">
        {transactions.map((transaction) => (
          <div key={transaction.id} className="flex items-center justify-between p-4 border border-gray-100 rounded-lg hover:bg-gray-50 transition-colors">
            <div className="flex items-center space-x-3">
              <div className={`p-2 rounded-full ${
                transaction.type === 'sell' 
                  ? 'bg-green-100 text-green-600' 
                  : 'bg-blue-100 text-blue-600'
              }`}>
                {transaction.type === 'sell' ? (
                  <ArrowUpRight className="w-4 h-4" />
                ) : (
                  <ArrowDownLeft className="w-4 h-4" />
                )}
              </div>
              
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-medium text-gray-900">
                    {transaction.type === 'sell' ? 'Sold to' : 'Bought from'}
                  </span>
                  <span className="text-gray-600">
                    {transaction.type === 'sell' ? transaction.buyer : transaction.seller}
                  </span>
                </div>
                <div className="text-sm text-gray-500 flex items-center space-x-2">
                  <Clock className="w-3 h-3" />
                  <span>{transaction.time}</span>
                </div>
              </div>
            </div>

            <div className="text-right">
              <div className="font-semibold text-gray-900">{transaction.price}</div>
              <div className="text-sm text-gray-600">{transaction.amount}</div>
              <div className={`text-xs px-2 py-1 rounded-full mt-1 ${
                transaction.status === 'completed'
                  ? 'bg-green-100 text-green-700'
                  : 'bg-yellow-100 text-yellow-700'
              }`}>
                {transaction.status}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RecentTransactions;