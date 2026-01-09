import { useState } from "react";
import {
  FileText,
  AlertTriangle,
  Info,
  List,
  Scale,
  AlertCircle,
  File,
  CheckCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { BACKEND_URL } from "../../api";

/* ===================== TYPES ===================== */

interface KeyClause {
  title: string;
  severity: "info" | "warning" | "critical";
}

interface AnalysisResult {
  keyClauses: KeyClause[];
  plainLanguageExplanation: string;
  possibleFutureImpact: string[];
}

/* ===================== COMPONENT ===================== */

const TermsContent = () => {
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [termsText, setTermsText] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  /* ===================== ANALYZE HANDLER ===================== */
  const handleAnalyze = async () => {
    try {
      setIsAnalyzing(true);
      console.log("BUTTON CLICKED - TERMS");

      const response = await fetch(`${BACKEND_URL}/api/terms/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          websiteUrl,
          termsText,
        }),
      });

      const data = await response.json();

      setResult({
        keyClauses: data.summaryPoints.map((point: string) => ({
          title: point,
          severity: data.finalRiskLevel === "HIGH" ? "critical" : "warning",
        })),
        plainLanguageExplanation:
          "Potentially risky clauses were identified in these terms.",
        possibleFutureImpact: data.summaryPoints,
      });
    } catch (error) {
      console.error("Terms analysis failed", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  /* ===================== HELPERS ===================== */

  const getSeverityStyles = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-destructive/10 text-destructive border-destructive/20";
      case "warning":
        return "bg-warning/10 text-warning border-warning/20";
      default:
        return "bg-primary/10 text-primary border-primary/20";
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical":
        return <AlertCircle className="w-4 h-4" />;
      case "warning":
        return <AlertTriangle className="w-4 h-4" />;
      default:
        return <Info className="w-4 h-4" />;
    }
  };

  /* ===================== UI ===================== */

  return (
    <div className="space-y-8 animate-fade-in">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Scale className="w-6 h-6 text-primary" />
          <h2 className="text-2xl font-semibold text-foreground">
            Terms & Conditions Impact Analysis
          </h2>
        </div>
      </div>

      

      <div className="max-w-2xl mx-auto space-y-6">
        <input
          type="url"
          placeholder="Paste the website URL"
          value={websiteUrl}
          onChange={(e) => setWebsiteUrl(e.target.value)}
          className="input-search"
        />

        <textarea
          placeholder="Paste the complete Terms & Conditions text here…"
          value={termsText}
          onChange={(e) => setTermsText(e.target.value)}
          className="textarea-content min-h-[180px]"
        />

        <button
          onClick={handleAnalyze}
          disabled={!websiteUrl || !termsText || isAnalyzing}
          className="btn-primary w-full py-4 text-lg"
        >
          {isAnalyzing ? "Analyzing..." : "Analyze Terms Impact"}
        </button>

        {result && (
          <div className="mt-8 space-y-4 animate-slide-up">
            <div className="bg-card border border-border rounded-xl p-6 space-y-6 shadow-card">
              <div className="space-y-3">
                <h4 className="text-sm font-semibold flex items-center gap-2">
                  <FileText className="w-4 h-4 text-primary" />
                  Key Clauses Identified
                </h4>

                <div className="space-y-2 pl-6">
                  {result.keyClauses.map((clause, index) => (
                    <div
                      key={index}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-lg border text-sm",
                        getSeverityStyles(clause.severity)
                      )}
                    >
                      {getSeverityIcon(clause.severity)}
                      <span>{clause.title}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <h4 className="text-sm font-semibold flex items-center gap-2">
                  <Info className="w-4 h-4 text-primary" />
                  Plain-language Explanation
                </h4>
                <p className="text-muted-foreground text-sm pl-6">
                  {result.plainLanguageExplanation}
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="text-sm font-semibold flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-warning" />
                  Possible Future Impact
                </h4>

                <ul className="space-y-2 pl-6">
                  {result.possibleFutureImpact.map((item, index) => (
                    <li
                      key={index}
                      className="text-muted-foreground text-sm flex items-start gap-2"
                    >
                      <List className="w-4 h-4 mt-0.5 text-warning" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="pt-4 border-t border-border">
                <p className="text-muted-foreground text-xs italic flex gap-2">
                  <Info className="w-4 h-4" />
                  This is not legal advice. Consult a qualified attorney.
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TermsContent;
