import { useState } from "react";
import BrandHeader from "@/components/BrandHeader";
import TabNavigation from "@/components/TabNavigation";
import ActionTypeContent from "@/components/content/ActionTypeContent";
import PermissionsContent from "@/components/content/PermissionsContent";
import CookiesContent from "@/components/content/CookiesContent";
import TermsContent from "@/components/content/TermsContent";
import { Shield, Zap, Lock, Eye } from "lucide-react";

type TabType = "action" | "permissions" | "cookies" | "terms";

const Index = () => {
  const [activeTab, setActiveTab] = useState<TabType>("action");

  const renderContent = () => {
    switch (activeTab) {
      case "action":
        return <ActionTypeContent />;
      case "permissions":
        return <PermissionsContent />;
      case "cookies":
        return <CookiesContent />;
      case "terms":
        return <TermsContent />;
      default:
        return <ActionTypeContent />;
    }
  };

  const features = [
    { icon: Shield, label: "Security First", color: "from-primary to-accent-purple" },
    { icon: Zap, label: "Instant Analysis", color: "from-accent-cyan to-primary" },
    { icon: Lock, label: "Privacy Focus", color: "from-accent-purple to-accent-pink" },
    { icon: Eye, label: "Transparency", color: "from-accent-pink to-accent-yellow" },
  ];

  return (
    <div className="min-h-screen bg-background relative overflow-hidden">
      {/* Animated mesh gradient background */}
      <div className="fixed inset-0 animated-gradient-bg pointer-events-none" />
      
      {/* Floating orbs */}
      <div className="fixed top-20 left-10 w-72 h-72 bg-primary/20 rounded-full blur-3xl animate-float pointer-events-none" />
      <div className="fixed bottom-20 right-10 w-96 h-96 bg-accent-purple/15 rounded-full blur-3xl animate-float pointer-events-none" style={{ animationDelay: '-3s' }} />
      <div className="fixed top-1/2 left-1/2 w-64 h-64 bg-accent-cyan/10 rounded-full blur-3xl animate-float pointer-events-none" style={{ animationDelay: '-1.5s' }} />

      <div className="relative max-w-5xl mx-auto px-6 py-8">
        <BrandHeader />

        {/* Feature badges */}
        <div className="flex flex-wrap justify-center gap-3 mb-8 animate-fade-in">
          {features.map((feature, index) => (
            <div
              key={feature.label}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-card/80 backdrop-blur-sm border border-border/50 transition-all duration-300 hover:border-primary/40 hover:-translate-y-0.5 hover:shadow-glow-primary"
              style={{ animationDelay: `${index * 0.1}s` }}
            >
              <div className={`p-1.5 rounded-lg bg-gradient-to-br ${feature.color}`}>
                <feature.icon className="w-3.5 h-3.5 text-white" />
              </div>
              <span className="text-xs font-medium text-foreground">{feature.label}</span>
            </div>
          ))}
        </div>
        
        {/* Main card with glass effect */}
        <div className="glass-card overflow-hidden animate-slide-up">
          {/* Gradient top border */}
          <div className="h-1 bg-gradient-to-r from-primary via-accent-purple to-accent-cyan" />
          
          <div className="p-4 border-b border-border/50">
            <TabNavigation activeTab={activeTab} onTabChange={setActiveTab} />
          </div>
          
          <div className="p-6 md:p-8" key={activeTab}>
            <div className="content-fade-in">
              {renderContent()}
            </div>
          </div>
        </div>

        {/* Stats section */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8 animate-fade-in" style={{ animationDelay: '0.3s' }}>
          {[
            { value: "10K+", label: "Scans Today", gradient: "from-primary to-accent-purple" },
            { value: "99.9%", label: "Accuracy", gradient: "from-accent-cyan to-primary" },
            { value: "50ms", label: "Avg Response", gradient: "from-accent-purple to-accent-pink" },
            { value: "24/7", label: "Protection", gradient: "from-accent-pink to-accent-yellow" },
          ].map((stat) => (
            <div key={stat.label} className="feature-card text-center group">
              <div className={`text-2xl font-bold font-display bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}>
                {stat.value}
              </div>
              <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
            </div>
          ))}
        </div>

        <footer className="mt-10 text-center animate-fade-in" style={{ animationDelay: '0.4s' }}>
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-card/60 backdrop-blur-sm border border-border/30">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <p className="text-xs text-muted-foreground">
              Powered by <span className="font-semibold gradient-text">BeforeClick</span> • Global Hackathon 2024
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Index;
