import { useState } from "react";
import { 
  Camera, 
  Mic, 
  FileText, 
  Image, 
  MapPin, 
  Bell, 
  Clipboard, 
  Users, 
  Monitor,
  Globe,
  Shield,
  AlertTriangle,
  CheckCircle,
  Info,
  Search
} from "lucide-react";

interface Permission {
  id: string;
  name: string;
  icon: React.ReactNode;
}

interface AnalysisResult {
  riskLevel: "low" | "medium" | "high";
  justification: string;
  isNecessary: boolean;
  impactExplanation: string;
  recommendation: string;
}

const permissions: Permission[] = [
  { id: "camera", name: "Camera", icon: <Camera className="w-6 h-6" /> },
  { id: "microphone", name: "Microphone", icon: <Mic className="w-6 h-6" /> },
  { id: "file-access", name: "File Access", icon: <FileText className="w-6 h-6" /> },
  { id: "image-access", name: "Image Access", icon: <Image className="w-6 h-6" /> },
  { id: "location", name: "Location", icon: <MapPin className="w-6 h-6" /> },
  { id: "notifications", name: "Notifications", icon: <Bell className="w-6 h-6" /> },
  { id: "clipboard", name: "Clipboard", icon: <Clipboard className="w-6 h-6" /> },
  { id: "contacts", name: "Contacts", icon: <Users className="w-6 h-6" /> },
  { id: "screen-sharing", name: "Screen Sharing", icon: <Monitor className="w-6 h-6" /> },
];

const PermissionTile = ({ 
  permission, 
  isSelected, 
  onClick 
}: { 
  permission: Permission; 
  isSelected: boolean; 
  onClick: () => void;
}) => (
  <button
    onClick={onClick}
    className={`
      group relative flex flex-col items-center justify-center gap-3 p-4 rounded-xl
      border transition-all duration-200 min-h-[100px]
      ${isSelected 
        ? "bg-secondary border-primary shadow-glow" 
        : "bg-card border-border hover:border-primary/50"
      }
    `}
  >
    <div className={`
      p-3 rounded-lg transition-all duration-200
      ${isSelected 
        ? "bg-primary text-primary-foreground" 
        : "bg-muted text-muted-foreground group-hover:text-primary"
      }
    `}>
      {permission.icon}
    </div>
    <span className={`
      text-sm font-medium text-center transition-colors duration-200
      ${isSelected ? "text-foreground" : "text-muted-foreground group-hover:text-foreground"}
    `}>
      {permission.name}
    </span>
    {isSelected && (
      <div className="absolute top-2 right-2">
        <CheckCircle className="w-4 h-4 text-primary" />
      </div>
    )}
  </button>
);

const getRiskBadgeStyles = (level: string) => {
  switch (level) {
    case "low":
      return "bg-success/10 text-success border-success/20";
    case "medium":
      return "bg-warning/10 text-warning border-warning/20";
    case "high":
      return "bg-destructive/10 text-destructive border-destructive/20";
    default:
      return "bg-muted text-muted-foreground border-border";
  }
};

const getRiskIcon = (level: string) => {
  switch (level) {
    case "low":
      return <CheckCircle className="w-5 h-5" />;
    case "medium":
      return <Info className="w-5 h-5" />;
    case "high":
      return <AlertTriangle className="w-5 h-5" />;
    default:
      return <Shield className="w-5 h-5" />;
  }
};

const PermissionsContent = () => {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [selectedPermissions, setSelectedPermissions] = useState<string[]>([]);
  const [contextMessage, setContextMessage] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const togglePermission = (permissionId: string) => {
    setSelectedPermissions(prev => 
      prev.includes(permissionId)
        ? prev.filter(id => id !== permissionId)
        : [...prev, permissionId]
    );
    setResult(null);
  };

  const isAnalyzeEnabled = websiteUrl.trim() !== "" && selectedPermissions.length > 0;

  const handleAnalyze = async () => {
    if (!isAnalyzeEnabled) return;
    
    setIsAnalyzing(true);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const hasHighRiskPermission = selectedPermissions.some(p => 
      ["camera", "microphone", "location", "contacts", "screen-sharing"].includes(p)
    );
    const hasMediumRiskPermission = selectedPermissions.some(p => 
      ["file-access", "clipboard"].includes(p)
    );
    
    const riskLevel = hasHighRiskPermission ? "high" : hasMediumRiskPermission ? "medium" : "low";
    
    const selectedNames = selectedPermissions.map(id => 
      permissions.find(p => p.id === id)?.name
    ).join(", ");
    
    setResult({
      riskLevel,
      isNecessary: riskLevel === "low",
      justification: riskLevel === "low" 
        ? `The requested permissions (${selectedNames}) appear to be commonly used by websites of this type.`
        : `The requested permissions (${selectedNames}) may not be necessary for basic website functionality.`,
      impactExplanation: getImpactExplanation(selectedPermissions),
      recommendation: getRecommendation(riskLevel, selectedPermissions)
    });
    
    setIsAnalyzing(false);
  };

  const getImpactExplanation = (perms: string[]): string => {
    const explanations: Record<string, string> = {
      camera: "Camera access allows the website to capture photos and video through your device's camera.",
      microphone: "Microphone access enables the website to record audio from your device.",
      "file-access": "File access permits the website to read files from your device storage.",
      "image-access": "Image access allows the website to view and select photos from your gallery.",
      location: "Location access reveals your geographic position to the website.",
      notifications: "Notification permission allows the website to send you alerts even when not on the page.",
      clipboard: "Clipboard access lets the website read or write to your copy-paste clipboard.",
      contacts: "Contacts access allows the website to view your saved contacts.",
      "screen-sharing": "Screen sharing allows the website to view your entire screen or specific windows."
    };
    
    return perms.map(p => explanations[p] || "").filter(Boolean).join(" ");
  };

  const getRecommendation = (level: string, perms: string[]): string => {
    if (level === "low") {
      return "These permissions appear reasonable for the website's purpose. You may grant them if you trust the website.";
    } else if (level === "medium") {
      return "Consider whether you truly need the features requiring these permissions. You may grant them temporarily and revoke later if not needed.";
    } else {
      const highRiskPerms = perms.filter(p => 
        ["camera", "microphone", "location", "contacts", "screen-sharing"].includes(p)
      );
      const names = highRiskPerms.map(id => 
        permissions.find(p => p.id === id)?.name
      ).join(", ");
      return `${names} access is usually not required for typical websites. Consider denying or allowing only when actively using the feature.`;
    }
  };

  const handleReset = () => {
    setWebsiteUrl("");
    setSelectedPermissions([]);
    setContextMessage("");
    setResult(null);
  };

  return (
    <div className="animate-fade-in space-y-8">
      {/* Section Header */}
      <div className="space-y-2">
        <h2 className="text-2xl font-semibold text-foreground flex items-center gap-3">
          <Shield className="w-7 h-7 text-primary" />
          Permissions Request Analysis
        </h2>
        <p className="text-muted-foreground">
          Understand the impact of permissions before you allow them.
        </p>
      </div>

      {/* Step 1: Website URL Input */}
      <div className="space-y-3">
        <label className="text-sm font-medium text-foreground flex items-center gap-2">
          <Globe className="w-4 h-4 text-primary" />
          Website URL
        </label>
        <input
          type="url"
          value={websiteUrl}
          onChange={(e) => {
            setWebsiteUrl(e.target.value);
            setResult(null);
          }}
          placeholder="Enter the website URL requesting permissions"
          className="input-search"
        />
        <p className="text-xs text-muted-foreground">
          Example: https://example.com
        </p>
      </div>

      {/* Step 2: Permission Selection Grid */}
      <div className="space-y-4">
        <label className="text-sm font-medium text-foreground flex items-center gap-2">
          <CheckCircle className="w-4 h-4 text-primary" />
          Select Requested Permissions
        </label>
        <p className="text-xs text-muted-foreground">
          Click to select the permissions the website is requesting
        </p>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
          {permissions.map((permission) => (
            <PermissionTile
              key={permission.id}
              permission={permission}
              isSelected={selectedPermissions.includes(permission.id)}
              onClick={() => togglePermission(permission.id)}
            />
          ))}
        </div>
        {selectedPermissions.length > 0 && (
          <p className="text-sm text-primary font-medium">
            {selectedPermissions.length} permission{selectedPermissions.length > 1 ? "s" : ""} selected
          </p>
        )}
      </div>

      {/* Step 3: Optional Context */}
      <div className="space-y-3">
        <label className="text-sm font-medium text-foreground flex items-center gap-2">
          <FileText className="w-4 h-4 text-primary" />
          Context (Optional)
        </label>
        <textarea
          value={contextMessage}
          onChange={(e) => setContextMessage(e.target.value)}
          placeholder="Paste any message or instruction shown while asking for permission (optional)"
          rows={3}
          className="textarea-content"
        />
      </div>

      {/* Step 4: Analyze Button */}
      <div className="flex justify-center">
        <button
          onClick={handleAnalyze}
          disabled={!isAnalyzeEnabled || isAnalyzing}
          className="btn-primary px-8 py-3 flex items-center gap-3"
        >
          {isAnalyzing ? (
            <>
              <div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="w-5 h-5" />
              Analyze Permission Risk
            </>
          )}
        </button>
      </div>

      {/* Step 5: Results Section */}
      {result && (
        <div className="space-y-6 animate-slide-up">
          {/* Risk Level Badge */}
          <div className="flex items-center gap-4">
            <div className={`
              inline-flex items-center gap-2 px-4 py-2 rounded-full border
              font-medium ${getRiskBadgeStyles(result.riskLevel)}
            `}>
              {getRiskIcon(result.riskLevel)}
              <span className="capitalize">{result.riskLevel} Risk</span>
            </div>
          </div>

          {/* Permission Justification Check */}
          <div className="p-5 bg-card border border-border rounded-xl space-y-3 shadow-card">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <Info className="w-5 h-5 text-primary" />
              Permission Justification Check
            </h4>
            <div className="flex items-start gap-3">
              <div className={`
                p-1 rounded-full mt-0.5
                ${result.isNecessary ? "bg-success/10" : "bg-warning/10"}
              `}>
                {result.isNecessary 
                  ? <CheckCircle className="w-4 h-4 text-success" />
                  : <AlertTriangle className="w-4 h-4 text-warning" />
                }
              </div>
              <p className="text-muted-foreground leading-relaxed">
                {result.justification}
              </p>
            </div>
          </div>

          {/* Impact Explanation */}
          <div className="p-5 bg-card border border-border rounded-xl space-y-3 shadow-card">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              Impact Explanation
            </h4>
            <p className="text-muted-foreground leading-relaxed">
              {result.impactExplanation}
            </p>
          </div>

          {/* Recommendation */}
          <div className="p-5 bg-secondary border border-primary/20 rounded-xl space-y-3">
            <h4 className="font-semibold text-foreground flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-primary" />
              Recommendation
            </h4>
            <p className="text-muted-foreground leading-relaxed">
              {result.recommendation}
            </p>
          </div>

          {/* Reset Button */}
          <div className="flex justify-center pt-4">
            <button
              onClick={handleReset}
              className="btn-secondary px-6 py-2"
            >
              Analyze Another Website
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default PermissionsContent;
