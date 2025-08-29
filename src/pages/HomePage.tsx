import React from 'react';
import { Link } from 'react-router-dom';
import { Sun, Zap, Users, TrendingUp, Shield, Leaf, ArrowRight, Award } from 'lucide-react';

const HomePage = () => {
  const features = [
    {
      icon: <Zap className="w-8 h-8" />,
      title: "P2P Energy Trading",
      description: "Trade excess solar power directly with your neighbors and community.",
    },
    {
      icon: <Users className="w-8 h-8" />,
      title: "Community Solar Pools",
      description: "Join shared solar farms even if you can't install your own panels.",
    },
    {
      icon: <TrendingUp className="w-8 h-8" />,
      title: "Investment Hub",
      description: "Invest in local solar projects and earn returns while helping the environment.",
    },
    {
      icon: <Shield className="w-8 h-8" />,
      title: "Blockchain Security",
      description: "Transparent, secure energy transactions with full traceability.",
    },
    {
      icon: <Leaf className="w-8 h-8" />,
      title: "Agri-Solar Integration",
      description: "Combine agriculture with solar farming for maximum land efficiency.",
    },
    {
      icon: <Award className="w-8 h-8" />,
      title: "Green Token Rewards",
      description: "Earn rewards for contributing to Sri Lanka's renewable energy future.",
    },
  ];

  const stats = [
    { value: "2.5MW", label: "Energy Shared" },
    { value: "1,247", label: "Active Users" },
    { value: "85", label: "Communities" },
    { value: "12,500", label: "CO₂ Tonnes Saved" },
  ];

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-orange-600 via-orange-500 to-yellow-400 text-white">
        <div className="absolute inset-0 bg-black/10"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6 leading-tight">
              Power Sri Lanka's
              <span className="block text-yellow-200">Green Future</span>
            </h1>
            <p className="text-xl md:text-2xl mb-8 max-w-3xl mx-auto text-orange-100">
              Join the community-driven renewable energy marketplace. 
              Share solar power, earn rewards, and build a sustainable tomorrow.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <Link
                to="/dashboard"
                className="bg-white text-orange-600 px-8 py-3 rounded-full font-semibold hover:bg-orange-50 transition-colors duration-200 flex items-center space-x-2"
              >
                <span>Get Started</span>
                <ArrowRight className="w-5 h-5" />
              </Link>
              <Link
                to="/community"
                className="border-2 border-white px-8 py-3 rounded-full font-semibold hover:bg-white hover:text-orange-600 transition-colors duration-200"
              >
                Join Community
              </Link>
            </div>
          </div>
        </div>
        <div className="absolute bottom-0 left-0 right-0">
          <svg className="w-full h-12" viewBox="0 0 1200 120" preserveAspectRatio="none">
            <path d="M321.39,56.44c58-10.79,114.16-30.13,172-41.86,82.39-16.72,168.19-17.73,250.45-.39C823.78,31,906.67,72,985.66,92.83c70.05,18.48,146.53,26.09,214.34,3V0H0V27.35A600.21,600.21,0,0,0,321.39,56.44Z" 
                  fill="#ffffff"></path>
          </svg>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-16 bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-3xl md:text-4xl font-bold text-orange-600 mb-2">
                  {stat.value}
                </div>
                <div className="text-gray-600">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-4">
              Why Choose SolarShare.lk?
            </h2>
            <p className="text-xl text-gray-600 max-w-3xl mx-auto">
              We're revolutionizing how Sri Lanka generates, shares, and benefits from renewable energy.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <div
                key={index}
                className="bg-white p-8 rounded-xl shadow-lg hover:shadow-xl transition-shadow duration-300"
              >
                <div className="text-orange-600 mb-4">{feature.icon}</div>
                <h3 className="text-xl font-semibold text-gray-900 mb-3">
                  {feature.title}
                </h3>
                <p className="text-gray-600">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Sri Lanka Specific Section */}
      <section className="py-20 bg-gradient-to-r from-green-600 to-orange-600 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <h2 className="text-3xl md:text-4xl font-bold mb-6">
              Built for Sri Lanka
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-12">
              <div className="text-center">
                <div className="bg-white/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Sun className="w-8 h-8" />
                </div>
                <h3 className="text-xl font-semibold mb-2">Weather Integration</h3>
                <p className="text-green-100">Real-time weather data for accurate solar predictions</p>
              </div>
              <div className="text-center">
                <div className="bg-white/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Shield className="w-8 h-8" />
                </div>
                <h3 className="text-xl font-semibold mb-2">Disaster Ready</h3>
                <p className="text-green-100">Priority energy distribution during emergencies</p>
              </div>
              <div className="text-center">
                <div className="bg-white/20 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Users className="w-8 h-8" />
                </div>
                <h3 className="text-xl font-semibold mb-2">Multi-Language</h3>
                <p className="text-green-100">Available in Sinhala, Tamil, and English</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-white">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-900 mb-6">
            Ready to Join the Solar Revolution?
          </h2>
          <p className="text-xl text-gray-600 mb-8">
            Start trading solar energy, earning rewards, and building a sustainable future for Sri Lanka today.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              to="/dashboard"
              className="bg-orange-600 text-white px-8 py-4 rounded-full font-semibold hover:bg-orange-700 transition-colors duration-200 flex items-center justify-center space-x-2"
            >
              <Sun className="w-5 h-5" />
              <span>Start Your Solar Journey</span>
            </Link>
            <Link
              to="/investment"
              className="border-2 border-orange-600 text-orange-600 px-8 py-4 rounded-full font-semibold hover:bg-orange-600 hover:text-white transition-colors duration-200"
            >
              Explore Investments
            </Link>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;