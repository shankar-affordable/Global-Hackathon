import { MousePointerClick, Shield } from "lucide-react";
import ThemeToggle from "./ThemeToggle";

const BrandHeader = () => {
  return (
    <div className="flex items-center justify-between mb-10">
      <div className="flex items-center gap-4">
        <div className="relative group">
          {/* Animated glow ring */}
          <div className="absolute -inset-1 bg-gradient-to-r from-primary via-accent-purple to-accent-cyan rounded-2xl blur-lg opacity-60 group-hover:opacity-100 transition-opacity duration-500 animate-pulse-glow" />
          
          {/* Icon container */}
          <div className="relative p-3.5 rounded-2xl bg-gradient-to-br from-primary to-accent-purple shadow-glow-primary animate-float">
            <MousePointerClick className="w-8 h-8 text-white" />
          </div>
        </div>
        
        <div>
          <h1 className="text-2xl font-bold font-display gradient-text">
            BeforeClick
          </h1>
          <p className="text-sm text-muted-foreground font-medium flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5 text-primary" />
            Think before you click
          </p>
        </div>
      </div>

      <ThemeToggle />
    </div>
  );
};

export default BrandHeader;
