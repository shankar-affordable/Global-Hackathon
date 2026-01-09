import { useState, useEffect } from "react";
import { Lock, CreditCard, FileSearch, Mail, MessageSquare, Upload, AlertTriangle, CheckCircle, Info, Shield, Globe, Smartphone, Phone, MessageCircle, HelpCircle, KeyRound, Wallet, RotateCcw, MonitorSmartphone, Loader } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { BACKEND_URL } from "../../api";
import { useResultContext } from "../../context/ResultContext";

type ActionType = "otp" | "payment" | "file" | null;
type OtpType = "sms" | "email" | null;
type OtpPurpose = "login" | "payment" | "password" | "device" | "unknown" | null;
type OtpSource = "website" | "app" | "call" | "message" | "unknown" | null;
type PaymentRange = "tiny" | "small" | "medium" | "large" | null;
type RiskLevel = "low" | "medium" | "high" | null;

interface AnalysisResult {
  riskLevel: RiskLevel;
  explanation: string;
  recommendation: string;
  additionalInfo?: string;
  aiExplanation?: string;
  domainAgeDays?: number | null;
  phishtankInfo?: {
    phish_id: string;
    submission_time: string;
    verified_time: string;
    phish_detail_page: string;
    target: string;
  } | null;
  checks?: {
    rdap?: { status: string; data?: any; error?: string };
    phishing?: { status: string; data?: any; error?: string };
    virusTotal?: { status: string; data?: any; error?: string };
  };
  virusTotal?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    totalEngines: number;
    detectionPercentage: number;
  } | null;
}

interface RdapResult {
  domainAge?: number;
  registrar?: string;
  createdDate?: string;
  updatedDate?: string;
  status: string;
  error?: string;
}

const ActionTypeContent = () => {
  const [selectedAction, setSelectedAction] = useState<ActionType>(null);
  const [otpType, setOtpType] = useState<OtpType>(null);
  const [otpPurpose, setOtpPurpose] = useState<OtpPurpose>(null);
  const [otpSource, setOtpSource] = useState<OtpSource>(null);
  const [paymentRange, setPaymentRange] = useState<PaymentRange>(null);
  const [initiatedPayment, setInitiatedPayment] = useState<boolean | null>(null);
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [rdapDomain, setRdapDomain] = useState("");
  const [rdapResult, setRdapResult] = useState<RdapResult | null>(null);
  const [isLoadingRdap, setIsLoadingRdap] = useState(false);
  const [messageText, setMessageText] = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [termsUrl, setTermsUrl] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const { setFileResult } = useResultContext();
  const BACKEND_URL = "http://localhost:5000";

  // RDAP lookup effect - fetch immediately when domain is entered
  useEffect(() => {
    if (!rdapDomain.trim()) {
      setRdapResult(null);
      return;
    }

    const timer = setTimeout(() => {
      fetchRdapData(rdapDomain);
    }, 800); // Debounce by 800ms

    return () => clearTimeout(timer);
  }, [rdapDomain]);

  const fetchRdapData = async (domain: string) => {
    try {
      setIsLoadingRdap(true);
      // Normalize domain - remove protocol if present
      let normalizedDomain = domain.trim();
      normalizedDomain = normalizedDomain.replace(/^(https?:\/\/)?(www\.)?/, "");

      const response = await fetch(`${BACKEND_URL}/api/rdap/lookup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: normalizedDomain }),
      });

      const data = await response.json();
      
      if (response.ok) {
        setRdapResult({
          domainAge: data.domainAgeDays,
          registrar: data.registrar,
          createdDate: data.createdDate,
          updatedDate: data.updatedDate,
          status: "completed",
        });
      } else {
        setRdapResult({
          status: "error",
          error: data.error || "Failed to fetch RDAP data",
        });
      }
    } catch (err) {
      console.error("RDAP fetch error:", err);
      setRdapResult({
        status: "error",
        error: "Unable to fetch RDAP data",
      });
    } finally {
      setIsLoadingRdap(false);
    }
  };


  const resetFlow = () => {
    setOtpType(null);
    setOtpPurpose(null);
    setOtpSource(null);
    setPaymentRange(null);
    setInitiatedPayment(null);
    setWebsiteUrl("");
    setMessageText("");
    setSelectedFile(null);
    setTermsUrl("");
    setResult(null);
  };

  const handleActionSelect = (action: ActionType) => {
    setSelectedAction(action);
    resetFlow();
  };

 const handleAnalyze = async () => {
  try {
    setIsAnalyzing(true);
    console.log("ANALYZE CLICKED", selectedAction);

    // Normalize the website URL: trim and ensure it starts with a protocol.
    let normalizedUrl = (websiteUrl || "").trim();
    if (normalizedUrl && !/^https?:\/\//i.test(normalizedUrl)) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    let response;
    let data: any;

    if (selectedAction === "otp") {
      response = await fetch(`${BACKEND_URL}/api/otp/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          websiteUrl: normalizedUrl,
          otpPurpose,
          otpType,
          otpMessageText: messageText,
        }),
      });

      data = await response.json();
      console.log("📊 OTP Response - Full data:", data);
      console.log("🔍 Checks data:", data?.checks);

      // Check for CRITICAL warning first
      if (data.warning === true && data.finalRiskLevel === "CRITICAL") {
        window.alert(`🚨 Dangerous Action Blocked\n\n${data.aiExplanation}`);
      }
      // Then check for HIGH warning
      else if (data.warning === true && data.finalRiskLevel === "HIGH") {
        console.warn("HIGH RISK WARNING:", data.aiExplanation);
        // Non-blocking warning - will be shown via result display
      }

      const riskLevel = (data?.finalRiskLevel?.toLowerCase() ?? "medium") as RiskLevel;
      const explanation = (Array.isArray(data?.riskReasons) && data?.riskReasons.length > 0)
        ? data.riskReasons.join(". ")
        : (data?.riskReasons ? String(data.riskReasons) : "No major risk indicators detected");
      const recommendation = data?.recommendedAction ?? "Verify through official channel";

      setResult({
        riskLevel,
        explanation,
        recommendation,
        domainAgeDays: data?.domainAgeDays,
        phishtankInfo: data?.phishtankInfo,
        checks: data?.checks,
        virusTotal: data?.virusTotal,
        aiExplanation: data?.aiExplanation,
      });
    }

    if (selectedAction === "payment") {
      response = await fetch(`${BACKEND_URL}/api/payment/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          websiteUrl: normalizedUrl,
          paymentAmountRange: paymentRange?.toUpperCase(),
          paymentInitiatedByUser: initiatedPayment,
          paymentInstructionText: messageText,
        }),
      });

      data = await response.json();
      console.log("📊 Payment Response - Full data:", data);
      console.log("🔍 Checks data:", data?.checks);

      // Check for CRITICAL warning first
      if (data.warning === true && data.finalRiskLevel === "CRITICAL") {
        window.alert(`🚨 Dangerous Action Blocked\n\n${data.aiExplanation}`);
      }
      // Then check for HIGH warning
      else if (data.warning === true && data.finalRiskLevel === "HIGH") {
        console.warn("HIGH RISK WARNING:", data.aiExplanation);
        // Non-blocking warning - will be shown via result display
      }

      const riskLevel = String(data?.finalRiskLevel ?? "medium").toLowerCase() as RiskLevel;
      const explanation = Array.isArray(data?.riskReasons) && data.riskReasons.length > 0
        ? data.riskReasons.join(". ")
        : (data?.riskReasons ? String(data.riskReasons) : "No strong risk indicators detected from domain analysis");
      const recommendation = data?.recommendedAction ?? "VERIFY THROUGH OFFICIAL CHANNEL";

      setResult({
        riskLevel,
        explanation,
        recommendation,
        additionalInfo: data?.inferredPaymentMethod,
        domainAgeDays: data?.domainAgeDays,
        phishtankInfo: data?.phishtankInfo,
        checks: data?.checks,
        virusTotal: data?.virusTotal,
        aiExplanation: data?.aiExplanation,
      });
    }

    if (selectedAction === "file") {
      if (!selectedFile) {
        alert("Please select a file to scan");
        return;
      }

      const formData = new FormData();
      formData.append("file", selectedFile);

      response = await fetch(`${BACKEND_URL}/api/file/analyze`, {
        method: "POST",
        body: formData,
      });

      data = await response.json();
      console.log("📊 File Scan Response - Full data:", data);

      // Support multiple backend response shapes (demo vs full)
      const backendFinalLevel = data?.finalRiskLevel || data?.analysisSummary?.finalRiskLevel || data?.finalRisk || "LOW";
      const riskLevel = String(backendFinalLevel).toLowerCase() as RiskLevel;
      const explanation = data?.aiExplanation || data?.aiExplanationText || "File analysis completed";
      const recommendation = data?.recommendedAction || data?.recommendation || "Review file carefully before opening";

      // Store in global context for Terms tab
      // update global context so Terms tab can read it
      console.log("Setting fileResult in context:", { fileName: selectedFile.name, riskLevel, explanation, recommendation });
      setFileResult({
        fileName: selectedFile.name,
        riskLevel: (riskLevel as any) || "low",
        aiExplanation: explanation,
        recommendation: recommendation,
        scanStatus: data?.scanStatus,
        fileSize: selectedFile.size,
      });

      setResult({
        riskLevel,
        explanation,
        recommendation,
        aiExplanation: data?.aiExplanation,
        additionalInfo: JSON.stringify({
          fileName: selectedFile.name,
          fileSize: selectedFile.size,
          scanStatus: data?.scanStatus,
        }),
      });
    }
  } catch (err) {
    console.error("Analysis failed", err);
  } finally {
    setIsAnalyzing(false);
  }
};



  const getRiskBadgeStyles = (level: RiskLevel) => {
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

  const getRiskIcon = (level: RiskLevel) => {
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

  const otpPurposeOptions = [
    { id: "login", label: "Login / Account access", icon: <KeyRound className="w-4 h-4" /> },
    { id: "payment", label: "Payment confirmation", icon: <Wallet className="w-4 h-4" /> },
    { id: "password", label: "Password reset", icon: <RotateCcw className="w-4 h-4" /> },
    { id: "device", label: "Device verification", icon: <MonitorSmartphone className="w-4 h-4" /> },
    { id: "unknown", label: "I don't know", icon: <HelpCircle className="w-4 h-4" /> },
  ];

  const otpSourceOptions = [
    { id: "website", label: "Website", icon: <Globe className="w-4 h-4" /> },
    { id: "app", label: "Mobile App", icon: <Smartphone className="w-4 h-4" /> },
    { id: "call", label: "Phone Call", icon: <Phone className="w-4 h-4" /> },
    { id: "message", label: "Message / Chat", icon: <MessageCircle className="w-4 h-4" /> },
    { id: "unknown", label: "Unknown", icon: <HelpCircle className="w-4 h-4" /> },
  ];

  const paymentRangeOptions = [
    { id: "tiny", label: "Very small (₹0–₹100)" },
    { id: "small", label: "Small (₹100–₹1,000)" },
    { id: "medium", label: "Medium (₹1,000–₹10,000)" },
    { id: "large", label: "Large (₹10,000+)" },
  ];

  return (
    <div className="space-y-8 animate-fade-in">
      {/* Section Title */}
      <div className="text-center mb-8">
        <h2 className="text-2xl font-semibold text-foreground mb-2">
          Select the action you are about to perform
        </h2>
      </div>

      {/* Action Buttons - Row 1: OTP (50%) + Payment (50%) */}
      <div className="max-w-3xl mx-auto space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <ActionButton
            icon={<Lock className="w-6 h-6" />}
            label="OTP Action"
            isSelected={selectedAction === "otp"}
            onClick={() => handleActionSelect("otp")}
            iconColor="text-accent-cyan"
          />
          <ActionButton
            icon={<CreditCard className="w-6 h-6" />}
            label="Payment Action"
            isSelected={selectedAction === "payment"}
            onClick={() => handleActionSelect("payment")}
            iconColor="text-accent-purple"
          />
        </div>

        {/* Row 2: File Scan (100%) */}
        <ActionButton
          icon={<div className="flex items-center gap-2"><FileSearch className="w-6 h-6" /><Shield className="w-5 h-5" /></div>}
          label="File Scan"
          isSelected={selectedAction === "file"}
          onClick={() => handleActionSelect("file")}
          fullWidth
          iconColor="text-accent-pink"
        />
      </div>

      {/* Flow Content */}
      <div className="max-w-2xl mx-auto">
        {selectedAction === "otp" && (
          <div className="space-y-6 animate-slide-up">
            {/* Website URL Input */}
            <div className="space-y-2">
              <input
                type="url"
                placeholder="Enter the website URL"
                value={websiteUrl}
                onChange={(e) => setWebsiteUrl(e.target.value)}
                className="input-search"
              />
            </div>

            {/* OTP Purpose Selection */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">What is this OTP for?</label>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {otpPurposeOptions.map((option) => (
                  <SelectTile
                    key={option.id}
                    icon={option.icon}
                    label={option.label}
                    isSelected={otpPurpose === option.id}
                    onClick={() => setOtpPurpose(option.id as OtpPurpose)}
                  />
                ))}
              </div>
            </div>

            {/* OTP Source Selection */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">Where did you receive the OTP request?</label>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {otpSourceOptions.map((option) => (
                  <SelectTile
                    key={option.id}
                    icon={option.icon}
                    label={option.label}
                    isSelected={otpSource === option.id}
                    onClick={() => setOtpSource(option.id as OtpSource)}
                  />
                ))}
              </div>
            </div>

            {/* OTP Type Selection */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">OTP Type</label>
              <div className="flex gap-4">
                <OtpTypeButton
                  icon={<MessageSquare className="w-5 h-5" />}
                  label="SMS OTP"
                  isSelected={otpType === "sms"}
                  onClick={() => setOtpType("sms")}
                />
                <OtpTypeButton
                  icon={<Mail className="w-5 h-5" />}
                  label="Email OTP"
                  isSelected={otpType === "email"}
                  onClick={() => setOtpType("email")}
                />
              </div>
            </div>

            {/* Message Text Area */}
            <textarea
              placeholder="Paste the OTP message or email text here (optional)"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              className="textarea-content"
            />

            {/* Analyze Button */}
            <Button
              onClick={handleAnalyze}
              disabled={!websiteUrl || isAnalyzing}
              className="btn-primary w-full py-6 text-lg"
            >
              {isAnalyzing ? "Analyzing..." : "Analyze Risk"}
            </Button>
          </div>
        )}

        {selectedAction === "payment" && (
          <div className="space-y-6 animate-slide-up">
            {/* Domain RDAP Lookup Section */}
            <div className="space-y-3 pb-6 border-b border-border">
              <label className="text-sm font-medium text-foreground">Check Domain RDAP Information</label>
              <input
                type="text"
                placeholder="Enter domain (e.g., example.com or https://example.com)"
                value={rdapDomain}
                onChange={(e) => setRdapDomain(e.target.value)}
                className="input-search"
              />
              
              {/* RDAP Loading State */}
              {isLoadingRdap && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader className="w-4 h-4 animate-spin" />
                  Fetching RDAP data...
                </div>
              )}
              
              {/* RDAP Results */}
              {rdapResult && !isLoadingRdap && (
                <div className={cn(
                  "p-4 rounded-lg border",
                  rdapResult.status === "completed" ? "bg-success/10 border-success/30" : "bg-destructive/10 border-destructive/30"
                )}>
                  {rdapResult.status === "completed" && rdapResult.domainAge !== undefined ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-sm font-semibold text-success">
                        <CheckCircle className="w-4 h-4" />
                        Domain Information
                      </div>
                      <div className="text-sm text-muted-foreground space-y-1 pl-6">
                        <p>
                          <span className="font-medium text-foreground">Domain Age:</span> 
                          <span className="ml-2 font-semibold">{rdapResult.domainAge} days old</span>
                          {rdapResult.domainAge < 30 && <span className="ml-2 text-destructive">⚠️ Very new (HIGH RISK)</span>}
                          {rdapResult.domainAge >= 30 && rdapResult.domainAge < 180 && <span className="ml-2 text-warning">⚠️ Recently created (MEDIUM RISK)</span>}
                          {rdapResult.domainAge >= 180 && rdapResult.domainAge < 365 && <span className="ml-2 text-success">Moderate age</span>}
                          {rdapResult.domainAge >= 365 && <span className="ml-2 text-success">✓ Established domain</span>}
                        </p>
                        {rdapResult.registrar && (
                          <p>
                            <span className="font-medium text-foreground">Registrar:</span> 
                            <span className="ml-2">{rdapResult.registrar}</span>
                          </p>
                        )}
                        {rdapResult.createdDate && (
                          <p>
                            <span className="font-medium text-foreground">Created:</span> 
                            <span className="ml-2">{rdapResult.createdDate}</span>
                          </p>
                        )}
                        {rdapResult.updatedDate && (
                          <p>
                            <span className="font-medium text-foreground">Last Updated:</span> 
                            <span className="ml-2">{rdapResult.updatedDate}</span>
                          </p>
                        )}
                      </div>
                    </div>
                  ) : rdapResult.status === "error" ? (
                    <div className="flex items-center gap-2 text-sm text-destructive">
                      <AlertTriangle className="w-4 h-4" />
                      {rdapResult.error}
                    </div>
                  ) : null}
                </div>
              )}
            </div>

            {/* Website URL Input */}
            <input
              type="url"
              placeholder="Enter the website URL"
              value={websiteUrl}
              onChange={(e) => setWebsiteUrl(e.target.value)}
              className="input-search"
            />

            {/* Payment Amount Range */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">Payment Amount Range</label>
              <div className="grid grid-cols-2 gap-3">
                {paymentRangeOptions.map((option) => (
                  <SelectTile
                    key={option.id}
                    label={option.label}
                    isSelected={paymentRange === option.id}
                    onClick={() => setPaymentRange(option.id as PaymentRange)}
                  />
                ))}
              </div>
            </div>

            {/* Did you initiate this payment? */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">Did you start this payment yourself?</label>
              <div className="flex gap-4">
                <button
                  onClick={() => setInitiatedPayment(true)}
                  className={cn(
                    "flex-1 py-4 px-6 rounded-xl font-medium transition-all duration-300",
                    "border-2",
                    initiatedPayment === true
                      ? "border-success bg-success/10 text-success shadow-lg"
                      : "border-border bg-card text-muted-foreground hover:border-success/50"
                  )}
                >
                  Yes
                </button>
                <button
                  onClick={() => setInitiatedPayment(false)}
                  className={cn(
                    "flex-1 py-4 px-6 rounded-xl font-medium transition-all duration-300",
                    "border-2",
                    initiatedPayment === false
                      ? "border-destructive bg-destructive/10 text-destructive shadow-lg"
                      : "border-border bg-card text-muted-foreground hover:border-destructive/50"
                  )}
                >
                  No
                </button>
              </div>
            </div>

            {/* Message Text Area */}
            <textarea
              placeholder="Paste any payment-related instruction or message shown on the website (optional)"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              className="textarea-content"
            />

            {/* Analyze Button */}
            <Button
              onClick={handleAnalyze}
              disabled={!websiteUrl || isAnalyzing}
              className="btn-primary w-full py-6 text-lg"
            >
              {isAnalyzing ? "Analyzing..." : "Analyze Risk"}
            </Button>
          </div>
        )}

        {selectedAction === "file" && (
          <div className="space-y-6 animate-slide-up">
            {/* File Upload Section */}
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">Upload File for Scanning</label>
              <div className="border-2 border-dashed border-border rounded-lg p-8 hover:border-primary/50 transition-colors">
                <input
                  type="file"
                  onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                  className="hidden"
                  id="file-input"
                  accept="*"
                />
                <label htmlFor="file-input" className="flex flex-col items-center cursor-pointer">
                  <Upload className="w-8 h-8 text-muted-foreground mb-2" />
                  <p className="text-sm font-medium text-foreground">Choose a file to scan</p>
                  <p className="text-xs text-muted-foreground mt-1">Click to select file</p>
                  {selectedFile && (
                    <p className="text-sm text-success font-semibold mt-3">
                      ✓ {selectedFile.name}
                    </p>
                  )}
                </label>
              </div>
            </div>

            <p className="text-sm text-muted-foreground text-center">
              Upload a file to scan for malware and get analysis results
            </p>

            {/* Analyze Button */}
            <Button
              onClick={handleAnalyze}
              disabled={!selectedFile || isAnalyzing}
              className="btn-primary w-full py-6 text-lg"
            >
              {isAnalyzing ? "Scanning..." : "Scan File"}
            </Button>
          </div>
        )}

        {/* Result Section */}
        {result && (
          <div className="mt-8 space-y-4 animate-slide-up">
            <div className="glass-card border border-border rounded-xl p-6 space-y-4 shadow-card">
              {/* Risk Level Badge */}
              <div className="flex items-center gap-3">
                <span
                  className={cn(
                    "inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-medium capitalize animate-pulse-glow",
                    getRiskBadgeStyles(result.riskLevel)
                  )}
                >
                  {getRiskIcon(result.riskLevel)}
                  {result.riskLevel} Risk
                </span>
              </div>

              {/* Domain Age Info - For Both OTP and Payment */}
              {result.domainAgeDays !== null && result.domainAgeDays !== undefined && (
                <div className="space-y-2 pb-2 border-b border-border">
                  <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                    <Globe className="w-4 h-4 text-primary" />
                    Domain Information
                  </h4>
                  <p className="text-muted-foreground text-sm leading-relaxed pl-6">
                    Domain Age: <span className="font-semibold text-foreground">{result.domainAgeDays} days old</span>
                    {result.domainAgeDays < 30 && " ⚠️ (Very new - High risk)"}
                    {result.domainAgeDays >= 30 && result.domainAgeDays < 180 && " ⚠️ (Recently created - Medium risk)"}
                    {result.domainAgeDays >= 180 && result.domainAgeDays < 365 && " (Moderate age)"}
                    {result.domainAgeDays >= 365 && " ✓ (Established domain)"}
                  </p>
                </div>
              )}

              {/* PhishTank Information */}
              {result.phishtankInfo && (
                <div className="space-y-2 pb-2 border-b border-border bg-destructive/5 p-4 rounded-lg">
                  <h4 className="text-sm font-semibold text-destructive flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    PhishTank Intelligence Report
                  </h4>
                  <div className="text-muted-foreground text-sm leading-relaxed pl-6 space-y-1">
                    <p><span className="font-semibold text-foreground">Target Organization:</span> {result.phishtankInfo.target}</p>
                    <p><span className="font-semibold text-foreground">Verified Time:</span> {new Date(result.phishtankInfo.verified_time).toLocaleDateString()}</p>
                    <p><span className="font-semibold text-foreground">PhishTank ID:</span> {result.phishtankInfo.phish_id}</p>
                    <p className="text-xs text-destructive pt-2">This domain has been verified as a phishing attack by PhishTank</p>
                  </div>
                </div>
              )}

              {/* Explanation */}
              <div className="space-y-2">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Info className="w-4 h-4 text-primary" />
                  Explanation
                </h4>
                <p className="text-muted-foreground text-sm leading-relaxed pl-6">
                  {result.explanation}
                </p>
              </div>

              {/* Recommendation */}
              <div className="space-y-2">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-success" />
                  Recommendation
                </h4>
                <p className="text-muted-foreground text-sm leading-relaxed pl-6">
                  {result.recommendation}
                </p>
              </div>

              {/* AI Analysis - Azure OpenAI Explanation (always render block; show placeholder if empty) */}
              <div className="space-y-2 pt-4 border-t border-border bg-primary/5 p-4 rounded-lg">
                <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  AI Security Analysis
                </h4>
                <p className="text-muted-foreground text-sm leading-relaxed pl-6">
                  {result.aiExplanation && result.aiExplanation.length > 0
                    ? result.aiExplanation
                    : "No AI analysis available for this request."
                  }
                </p>
              </div>

              {/* Additional Info */}
              {result.additionalInfo && (
                <div className="space-y-2 pt-2 border-t border-border">
                  {(() => {
                    try {
                      const additionalData = JSON.parse(result.additionalInfo);
                      if (additionalData.concernTypes && additionalData.concernTypes.length > 0) {
                        return (
                          <div className="space-y-3">
                            <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                              <AlertTriangle className="w-4 h-4 text-warning" />
                              Concerns Detected
                            </h4>
                            <div className="grid grid-cols-1 gap-2 pl-6">
                              {additionalData.concernTypes.map((concern: string, idx: number) => (
                                <div key={idx} className="text-sm text-muted-foreground">
                                  <span className="text-warning font-bold">•</span> {concern}
                                </div>
                              ))}
                            </div>
                            {additionalData.totalConcerns && (
                              <p className="text-xs text-muted-foreground italic pt-2">
                                Total concerns found: {additionalData.totalConcerns}
                              </p>
                            )}
                          </div>
                        );
                      }
                      return <p className="text-muted-foreground text-xs italic">{result.additionalInfo}</p>;
                    } catch {
                      return <p className="text-muted-foreground text-xs italic">{result.additionalInfo}</p>;
                    }
                  })()}
                </div>
              )}

              {/* Detailed Checks Section - Always Show */}
              <div className="space-y-3 pt-4 border-t border-border">
                <h4 className="text-sm font-semibold text-foreground">Security Checks</h4>
                
                {/* Debug: Show if checks exist */}
                {!result.checks && (
                  <p className="text-xs text-muted-foreground">Checks data: {JSON.stringify(result.checks)}</p>
                )}
                
                {result.checks && (
                  <>
                    {/* RDAP Check */}
                    <div className="p-3 rounded-lg border bg-card/50">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4" />
                          <span className="font-medium text-sm">RDAP (Domain Age)</span>
                        </div>
                        <span className="text-xs px-2 py-1 rounded bg-muted text-muted-foreground">
                          {result.checks.rdap?.status?.toUpperCase() || "N/A"}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground pl-6 space-y-1">
                        {result.checks.rdap?.data?.domainAge !== undefined ? (
                          <p>Domain Age: {result.checks.rdap.data.domainAge} days</p>
                        ) : null}
                        {result.checks.rdap?.error ? (
                          <p className="text-yellow-600">{result.checks.rdap.error}</p>
                        ) : null}
                      </div>
                    </div>

                    {/* Phishing Check */}
                    <div className="p-3 rounded-lg border bg-card/50">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-4 h-4" />
                          <span className="font-medium text-sm">Phishing Detection</span>
                        </div>
                        <span className={cn(
                          "text-xs px-2 py-1 rounded",
                          result.checks.phishing?.data?.detected 
                            ? "bg-destructive/20 text-destructive"
                            : "bg-success/20 text-success"
                        )}>
                          {result.checks.phishing?.data?.detected ? "DETECTED" : result.checks.phishing?.status?.toUpperCase() || "N/A"}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground pl-6">
                        {result.checks.phishing?.data?.detected ? (
                          <p className="text-destructive">⚠️ Domain found in phishing database</p>
                        ) : (
                          <p>No phishing detected</p>
                        )}
                        {result.checks.phishing?.error && (
                          <p className="text-yellow-600 mt-1">{result.checks.phishing.error}</p>
                        )}
                      </div>
                    </div>

                    {/* VirusTotal Check */}
                    <div className="p-3 rounded-lg border bg-card/50">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4" />
                          <span className="font-medium text-sm">VirusTotal Reputation</span>
                        </div>
                        <span className={cn(
                          "text-xs px-2 py-1 rounded",
                          result.checks.virusTotal?.data?.malicious > 0
                            ? "bg-destructive/20 text-destructive"
                            : result.checks.virusTotal?.status === "completed"
                            ? "bg-success/20 text-success"
                            : "bg-warning/20 text-warning"
                        )}>
                          {result.checks.virusTotal?.status?.toUpperCase() || "N/A"}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground pl-6 space-y-1">
                        {result.checks.virusTotal?.data ? (
                          <>
                            <p>Malicious: <span className="font-semibold">{result.checks.virusTotal.data.malicious}</span></p>
                            <p>Suspicious: <span className="font-semibold">{result.checks.virusTotal.data.suspicious}</span></p>
                            <p>Harmless: <span className="font-semibold">{result.checks.virusTotal.data.harmless}</span></p>
                            <p>Detection Rate: <span className="font-semibold">{result.checks.virusTotal.data.detectionPercentage}%</span></p>
                          </>
                        ) : null}
                        {result.checks.virusTotal?.error && (
                          <p className="text-yellow-600 mt-2">{result.checks.virusTotal.error}</p>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Action Button Component
interface ActionButtonProps {
  icon: React.ReactNode;
  label: string;
  isSelected: boolean;
  onClick: () => void;
  fullWidth?: boolean;
  iconColor?: string;
}

const ActionButton = ({ icon, label, isSelected, onClick, fullWidth, iconColor = "text-primary" }: ActionButtonProps) => (
  <button
    onClick={onClick}
    className={cn(
      "group relative flex items-center justify-center gap-4 py-6 px-8 rounded-xl transition-all duration-300",
      "border hover:shadow-glow hover:-translate-y-1",
      fullWidth && "w-full",
      isSelected
        ? "border-primary bg-secondary shadow-glow"
        : "border-border bg-card hover:border-primary/50"
    )}
  >
    <div
      className={cn(
        "p-3 rounded-xl transition-all duration-300",
        isSelected
          ? "bg-primary text-primary-foreground animate-pulse-glow"
          : cn("bg-muted group-hover:bg-primary/10", iconColor)
      )}
    >
      {icon}
    </div>
    <span className="font-medium text-lg text-foreground">{label}</span>
    
    {/* Selection indicator */}
    {isSelected && (
      <div className="absolute top-3 right-3 w-3 h-3 rounded-full bg-primary animate-pulse" />
    )}
  </button>
);

// OTP Type Button Component
interface OtpTypeButtonProps {
  icon: React.ReactNode;
  label: string;
  isSelected: boolean;
  onClick: () => void;
}

const OtpTypeButton = ({ icon, label, isSelected, onClick }: OtpTypeButtonProps) => (
  <button
    onClick={onClick}
    className={cn(
      "flex-1 flex items-center justify-center gap-3 p-4 rounded-xl transition-all duration-300",
      "border hover:-translate-y-0.5",
      isSelected
        ? "border-primary bg-secondary text-primary shadow-glow"
        : "border-border bg-card text-muted-foreground hover:border-primary/50"
    )}
  >
    {icon}
    <span className="font-medium">{label}</span>
  </button>
);

// Select Tile Component
interface SelectTileProps {
  icon?: React.ReactNode;
  label: string;
  isSelected: boolean;
  onClick: () => void;
}

const SelectTile = ({ icon, label, isSelected, onClick }: SelectTileProps) => (
  <button
    onClick={onClick}
    className={cn(
      "flex items-center gap-2 p-3 rounded-xl transition-all duration-300 text-sm",
      "border hover:-translate-y-0.5",
      isSelected
        ? "border-primary bg-secondary text-primary shadow-glow"
        : "border-border bg-card text-muted-foreground hover:border-primary/50 hover:bg-secondary/50"
    )}
  >
    {icon && <span className={cn(isSelected ? "text-primary" : "text-muted-foreground")}>{icon}</span>}
    <span className="font-medium text-left">{label}</span>
  </button>
);

export default ActionTypeContent;
