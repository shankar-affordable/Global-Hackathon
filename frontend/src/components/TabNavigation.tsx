import { MousePointerClick, Shield, Cookie, FileText } from "lucide-react";
import { cn } from "@/lib/utils";

type TabType = "action" | "permissions" | "cookies" | "terms";

interface TabNavigationProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
}

const tabs = [
  { id: "action" as TabType, label: "Action", icon: MousePointerClick, color: "text-accent-cyan", bgColor: "bg-accent-cyan/10", borderColor: "border-accent-cyan" },
  { id: "permissions" as TabType, label: "Permissions", icon: Shield, color: "text-accent-purple", bgColor: "bg-accent-purple/10", borderColor: "border-accent-purple" },
  { id: "cookies" as TabType, label: "Cookies", icon: Cookie, color: "text-accent-yellow", bgColor: "bg-accent-yellow/10", borderColor: "border-accent-yellow" },
  { id: "terms" as TabType, label: "Terms & Conditions", icon: FileText, color: "text-accent-pink", bgColor: "bg-accent-pink/10", borderColor: "border-accent-pink" },
];

const TabNavigation = ({ activeTab, onTabChange }: TabNavigationProps) => {
  return (
    <nav className="flex flex-wrap gap-2">
      {tabs.map((tab, index) => {
        const Icon = tab.icon;
        const isActive = activeTab === tab.id;
        
        return (
          <button
            key={tab.id}
            onClick={() => onTabChange(tab.id)}
            className={cn(
              "flex items-center gap-2 px-5 py-3 text-sm font-medium transition-all duration-300 relative overflow-hidden group rounded-xl border-2",
              isActive 
                ? cn("shadow-lg", tab.bgColor, tab.borderColor, tab.color)
                : "border-border bg-card hover:border-primary/30 text-muted-foreground hover:text-foreground"
            )}
            style={{ animationDelay: `${index * 0.05}s` }}
          >
            {/* Hover shimmer effect for inactive tabs */}
            {!isActive && (
              <div className="absolute inset-0 -translate-x-full group-hover:translate-x-full transition-transform duration-700 bg-gradient-to-r from-transparent via-primary/10 to-transparent" />
            )}
            
            <Icon 
              className={cn(
                "w-5 h-5 transition-all duration-300",
                isActive ? cn("scale-110 animate-bounce-subtle", tab.color) : "group-hover:scale-110"
              )} 
            />
            <span className="hidden sm:inline relative font-semibold">{tab.label}</span>
            
            {/* Active indicator dot */}
            {isActive && (
              <span className={cn("absolute -top-1 -right-1 w-2 h-2 rounded-full animate-pulse", tab.color.replace("text-", "bg-"))} />
            )}
          </button>
        );
      })}
    </nav>
  );
};

export default TabNavigation;
