import { useState } from "react";
import { Cookie, AlertTriangle, CheckCircle, Info, List } from "lucide-react";
import { cn } from "@/lib/utils";

type ImpactLevel = "low" | "medium" | "high" | null;

interface AnalysisResult {
  impactLevel: ImpactLevel;
  dataUsage: string[];
  trackingBehavior: string[];
  longTermImplications: string[];
}

const CookiesContent = () => {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [cookieText, setCookieText] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handleAnalyze = async () => {
    setIsAnalyzing(true);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    
    setResult({
      impactLevel: "medium",
      dataUsage: [
        "Collects browsing history and page interactions",
        "Stores user preferences and settings locally",
        "May share aggregated data with analytics partners"
      ],
      trackingBehavior: [
        "Uses third-party cookies for advertising purposes",
        "Tracks user sessions across multiple visits",
        "Fingerprinting techniques may be employed"
      ],
      longTermImplications: [
        "Cookie data may be retained for up to 2 years",
        "Cross-site tracking enables personalized advertising",
        "Opting out may limit website functionality"
      ]
    });
    setIsAnalyzing(false);
  };

  const getImpactBadgeStyles = (level: ImpactLevel) => {
    switch (level) {
      case "low":
        return "bg-success/10 text-success border-success/20";
      case "medium":
        return "bg-warning/10 text-warning border-warning/20";
      case "high":
        return "bg-destructive/10 text-destructive border-destructive/20";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getImpactIcon = (level: ImpactLevel) => {
    switch (level) {
      case "low":
        return <CheckCircle className="w-5 h-5" />;
      case "medium":
        return <AlertTriangle className="w-5 h-5" />;
      case "high":
        return <AlertTriangle className="w-5 h-5" />;
      default:
        return <Info className="w-5 h-5" />;
    }
  };

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Section Title */}
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Cookie className="w-6 h-6 text-primary" />
          <h2 className="text-2xl font-semibold text-foreground">
            Cookie Consent Analysis
          </h2>
        </div>
      </div>

      <div className="max-w-2xl mx-auto space-y-6">
        {/* URL Input */}
        <input
          type="url"
          placeholder="Paste the website URL"
          value={websiteUrl}
          onChange={(e) => setWebsiteUrl(e.target.value)}
          className="input-search"
        />

        {/* Cookie Rules Text Area */}
        <textarea
          placeholder="Paste the full cookie consent text or rules shown on the website here…"
          value={cookieText}
          onChange={(e) => setCookieText(e.target.value)}
          className="textarea-content min-h-[180px]"
        />

        {/* Analyze Button */}
        <button
          onClick={handleAnalyze}
          disabled={!websiteUrl || !cookieText || isAnalyzing}
          className="btn-primary w-full py-4 text-lg"
        >
          {isAnalyzing ? "Analyzing..." : "Analyze Cookie Impact"}
        </button>

        {/* Result Section */}
        {result && (
          <div className="mt-8 space-y-4 animate-slide-up">
            <div className="bg-card border border-border rounded-xl p-6 space-y-6 shadow-card">
              {/* Impact Level Badge */}
              <div className="flex items-center gap-3">
                <span
                  className={cn(
                    "inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-medium capitalize",
                    getImpactBadgeStyles(result.impactLevel)
                  )}
                >
                  {getImpactIcon(result.impactLevel)}
                  {result.impactLevel} Impact
                </span>
              </div>

              {/* Data Usage */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Info className="w-4 h-4 text-primary" />
                  Data Usage
                </h4>
                <ul className="space-y-2 pl-6">
                  {result.dataUsage.map((item, index) => (
                    <li key={index} className="text-muted-foreground text-sm leading-relaxed flex items-start gap-2">
                      <List className="w-4 h-4 mt-0.5 text-primary flex-shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Tracking Behavior */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-warning" />
                  Tracking Behavior
                </h4>
                <ul className="space-y-2 pl-6">
                  {result.trackingBehavior.map((item, index) => (
                    <li key={index} className="text-muted-foreground text-sm leading-relaxed flex items-start gap-2">
                      <List className="w-4 h-4 mt-0.5 text-warning flex-shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Long-term Implications */}
              <div className="space-y-3">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-success" />
                  Long-term Implications
                </h4>
                <ul className="space-y-2 pl-6">
                  {result.longTermImplications.map((item, index) => (
                    <li key={index} className="text-muted-foreground text-sm leading-relaxed flex items-start gap-2">
                      <List className="w-4 h-4 mt-0.5 text-success flex-shrink-0" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CookiesContent;
