import React from 'react';

interface EnergyChartProps {
  period: string;
}

const EnergyChart: React.FC<EnergyChartProps> = ({ period }) => {
  // Mock data for different periods
  const data = {
    day: [
      { time: '6AM', generated: 0.5, consumed: 0.2 },
      { time: '9AM', generated: 2.8, consumed: 1.5 },
      { time: '12PM', generated: 4.2, consumed: 2.1 },
      { time: '3PM', generated: 3.8, consumed: 1.8 },
      { time: '6PM', generated: 1.5, consumed: 2.5 },
      { time: '9PM', generated: 0, consumed: 1.8 }
    ],
    week: [
      { time: 'Mon', generated: 28, consumed: 18 },
      { time: 'Tue', generated: 32, consumed: 22 },
      { time: 'Wed', generated: 25, consumed: 19 },
      { time: 'Thu', generated: 35, consumed: 24 },
      { time: 'Fri', generated: 30, consumed: 21 },
      { time: 'Sat', generated: 38, consumed: 16 },
      { time: 'Sun', generated: 33, consumed: 15 }
    ],
    month: [
      { time: 'Week 1', generated: 180, consumed: 120 },
      { time: 'Week 2', generated: 220, consumed: 145 },
      { time: 'Week 3', generated: 195, consumed: 135 },
      { time: 'Week 4', generated: 240, consumed: 160 }
    ]
  };

  const currentData = data[period as keyof typeof data];
  const maxValue = Math.max(...currentData.flatMap(d => [d.generated, d.consumed]));

  return (
    <div className="h-64 flex items-end space-x-4 px-4">
      {currentData.map((point, index) => (
        <div key={index} className="flex-1 flex flex-col items-center space-y-2">
          <div className="w-full flex flex-col items-center space-y-1">
            {/* Generated bar */}
            <div className="w-full flex flex-col items-center">
              <div
                className="w-8 bg-orange-500 rounded-t-md transition-all duration-300 hover:bg-orange-600"
                style={{ height: `${(point.generated / maxValue) * 150}px` }}
              ></div>
              <span className="text-xs text-orange-600 font-medium mt-1">
                {point.generated}{period === 'day' ? 'kW' : 'kWh'}
              </span>
            </div>
            
            {/* Consumed bar */}
            <div className="w-full flex flex-col items-center">
              <div
                className="w-8 bg-blue-500 rounded-t-md transition-all duration-300 hover:bg-blue-600"
                style={{ height: `${(point.consumed / maxValue) * 150}px` }}
              ></div>
              <span className="text-xs text-blue-600 font-medium mt-1">
                {point.consumed}{period === 'day' ? 'kW' : 'kWh'}
              </span>
            </div>
          </div>
          
          <span className="text-xs text-gray-600 font-medium">{point.time}</span>
        </div>
      ))}
      
      {/* Legend */}
      <div className="absolute top-4 right-4 flex space-x-4">
        <div className="flex items-center space-x-1">
          <div className="w-3 h-3 bg-orange-500 rounded"></div>
          <span className="text-sm text-gray-600">Generated</span>
        </div>
        <div className="flex items-center space-x-1">
          <div className="w-3 h-3 bg-blue-500 rounded"></div>
          <span className="text-sm text-gray-600">Consumed</span>
        </div>
      </div>
    </div>
  );
};

export default EnergyChart;