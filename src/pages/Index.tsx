import { useState } from "react";
import { Header } from "@/components/Header";
import { URLInput } from "@/components/URLInput";
import { AnalysisResult, ThreatLevel } from "@/components/AnalysisResult";
import { DetailedReport, UrlAnalysisData } from "@/components/DetailedReport";
import { Features } from "@/components/Features";
import { HowItWorks } from "@/components/HowItWorks";
import { Footer } from "@/components/Footer";
import { ShieldIcon } from "@/components/ShieldIcon";
import { 
  Lock, Globe, ExternalLink, Download, Megaphone, Ban, 
  Code, AlertTriangle, Cpu, FileWarning 
} from "lucide-react";

interface AnalysisFeature {
  name: string;
  status: "pass" | "warning" | "fail";
  description: string;
  icon: React.ReactNode;
}

interface AnalysisState {
  url: string;
  threatLevel: ThreatLevel;
  features: AnalysisFeature[];
  score: number;
  threatReasons: string[];
}

// Build features from real backend data
function buildFeaturesFromBackend(data: UrlAnalysisData & { threatIntelligence?: any }): { threatLevel: ThreatLevel; features: AnalysisFeature[]; score: number; threatReasons: string[] } {
  const ti = data.threatIntelligence;
  if (!ti) {
    // Fallback if no threat intelligence (shouldn't happen with new backend)
    return { threatLevel: "suspicious", features: [], score: 50, threatReasons: ["Analysis incomplete"] };
  }

  const ca = ti.contentAnalysis;
  const da = ti.domainAnalysis;

  const features: AnalysisFeature[] = [
    {
      name: "SSL Certificate",
      status: data.security.hasSSL ? "pass" : "fail",
      description: data.security.hasSSL ? "Website uses HTTPS encryption" : "No HTTPS - data sent in plain text",
      icon: <Lock className="w-5 h-5" />,
    },
    {
      name: "Domain Reputation",
      status: da.hasKnownDangerousKeyword ? "fail" : da.hasSuspiciousTld ? "warning" : "pass",
      description: da.hasKnownDangerousKeyword 
        ? "Domain matches known dangerous/piracy site patterns" 
        : da.hasSuspiciousTld 
          ? "Suspicious top-level domain" 
          : "Domain appears legitimate",
      icon: <Globe className="w-5 h-5" />,
    },
    {
      name: "Aggressive Ads & Popups",
      status: ca.popupScriptCount > 2 || ca.adNetworkCount > 5 ? "fail" 
        : ca.popupScriptCount > 0 || ca.adNetworkCount > 2 ? "warning" : "pass",
      description: ca.popupScriptCount > 2 
        ? `${ca.popupScriptCount} popup scripts & ${ca.adNetworkCount} ad network references found` 
        : ca.popupScriptCount > 0 
          ? `Popup scripts detected (${ca.popupScriptCount})` 
          : "No aggressive ads or popups detected",
      icon: <Megaphone className="w-5 h-5" />,
    },
    {
      name: "Redirect Behavior",
      status: ca.jsRedirectCount > 3 || data.redirectCount > 3 ? "fail" 
        : ca.jsRedirectCount > 0 || data.redirectCount > 1 ? "warning" : "pass",
      description: ca.jsRedirectCount > 0 
        ? `${ca.jsRedirectCount} JavaScript redirects + ${data.redirectCount} HTTP redirects detected` 
        : data.redirectCount > 0 
          ? `${data.redirectCount} HTTP redirect(s)` 
          : "Direct link with no hidden redirects",
      icon: <ExternalLink className="w-5 h-5" />,
    },
    {
      name: "Auto-Download Detection",
      status: ca.autoDownloadCount > 0 ? "fail" : "pass",
      description: ca.autoDownloadCount > 0 
        ? `${ca.autoDownloadCount} auto-download attempt(s) detected (APK/EXE/etc.)` 
        : "No automatic downloads detected",
      icon: <Download className="w-5 h-5" />,
    },
    {
      name: "Obfuscated Code",
      status: ca.obfuscationScore > 20 ? "fail" : ca.obfuscationScore > 5 ? "warning" : "pass",
      description: ca.obfuscationScore > 20 
        ? "Heavily obfuscated JavaScript - likely hiding malicious behavior" 
        : ca.obfuscationScore > 5 
          ? "Some obfuscated code detected" 
          : "No suspicious code obfuscation",
      icon: <Code className="w-5 h-5" />,
    },
    {
      name: "Crypto Mining",
      status: ca.hasCryptoMiner ? "fail" : "pass",
      description: ca.hasCryptoMiner 
        ? "Cryptocurrency mining script detected - uses your device resources" 
        : "No crypto miners detected",
      icon: <Cpu className="w-5 h-5" />,
    },
    {
      name: "Security Headers",
      status: !data.security.hasCSP && !data.security.hasHSTS ? "fail" 
        : !data.security.hasCSP || !data.security.hasHSTS ? "warning" : "pass",
      description: data.security.hasCSP && data.security.hasHSTS 
        ? "Strong security headers present" 
        : "Missing critical security headers (CSP/HSTS)",
      icon: <FileWarning className="w-5 h-5" />,
    },
    {
      name: "Banned Domain Check",
      status: da.hasIPAddress ? "fail" : da.isShortened ? "warning" : "pass",
      description: da.hasIPAddress 
        ? "Uses IP address instead of domain name" 
        : da.isShortened 
          ? "URL shortener - true destination hidden" 
          : "Domain is not in blocklist",
      icon: <Ban className="w-5 h-5" />,
    },
  ];

  return {
    threatLevel: ti.threatLevel as ThreatLevel,
    features,
    score: ti.threatScore,
    threatReasons: ti.threatReasons || [],
  };
}

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [analysis, setAnalysis] = useState<AnalysisState | null>(null);
  const [detailedData, setDetailedData] = useState<UrlAnalysisData | null>(null);
  const [detailedError, setDetailedError] = useState<string | null>(null);

  const handleAnalyze = async (url: string) => {
    setIsLoading(true);
    setAnalysis(null);
    setDetailedData(null);
    setDetailedError(null);

    try {
      const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
      const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
      
      if (!projectId || !anonKey) {
        setDetailedError('Backend not configured');
        setIsLoading(false);
        return;
      }

      const res = await fetch(
        `https://${projectId}.supabase.co/functions/v1/analyze-url`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'apikey': anonKey,
            'Authorization': `Bearer ${anonKey}`,
          },
          body: JSON.stringify({ url }),
        }
      );

      const resData = await res.json().catch(() => ({ error: 'Analysis failed' }));
      
      if (res.ok) {
        // Use REAL backend threat intelligence
        const { threatLevel, features, score, threatReasons } = buildFeaturesFromBackend(resData);
        setAnalysis({ url, threatLevel, features, score, threatReasons });
        setDetailedData(resData);
      } else {
        // Backend error (DNS, timeout, etc.) - show error + mark as suspicious
        setDetailedError(resData.error || 'Deep analysis failed');
        
        const errorType = resData.errorType;
        let threatLevel: ThreatLevel = "suspicious";
        let score = 30;
        let description = "Could not analyze - proceed with caution";
        
        if (errorType === 'DNS_ERROR') {
          threatLevel = "dangerous";
          score = 10;
          description = "Domain does not exist or has been taken down - highly suspicious";
        } else if (errorType === 'TIMEOUT') {
          threatLevel = "suspicious";
          score = 40;
          description = "Server did not respond - may be offline or blocking analysis";
        }
        
        setAnalysis({
          url,
          threatLevel,
          features: [{
            name: "Domain Reachability",
            status: "fail",
            description,
            icon: <AlertTriangle className="w-5 h-5" />,
          }],
          score,
          threatReasons: [resData.error || 'Analysis failed'],
        });
      }
    } catch (e) {
      console.error('Analysis error:', e);
      setDetailedError('Could not connect to analysis server');
    }

    setIsLoading(false);
  };

  const handleReset = () => {
    setAnalysis(null);
    setDetailedData(null);
    setDetailedError(null);
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      {/* Hero Section */}
      <section className="relative py-20 px-4 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,hsl(190_95%_50%/0.1)_0%,transparent_50%)]" />
        
        <div className="container mx-auto relative z-10">
          <div className="text-center mb-12">
            <div className="inline-flex items-center justify-center mb-6">
              <ShieldIcon 
                status={isLoading ? "scanning" : analysis?.threatLevel || "idle"} 
                className="w-20 h-20 animate-float" 
              />
            </div>
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              <span className="text-gradient">Deep Secure</span>
              <br />
              <span className="text-foreground">QR & URL Analyzer</span>
            </h1>
            <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8">
              Protect yourself from phishing, malware, and fraud. Our deep analysis system scans URLs and QR codes in real-time to keep you safe online.
            </p>
          </div>

          {!analysis ? (
            <URLInput onAnalyze={handleAnalyze} isLoading={isLoading} />
          ) : (
            <div className="space-y-6">
              <AnalysisResult
                url={analysis.url}
                threatLevel={analysis.threatLevel}
                features={analysis.features}
                score={analysis.score}
              />

              {/* Threat Reasons */}
              {analysis.threatReasons.length > 0 && analysis.threatLevel !== "safe" && (
                <div className="max-w-3xl mx-auto">
                  <div className="p-4 rounded-lg border border-destructive/30 bg-destructive/5">
                    <p className="text-sm font-semibold text-destructive mb-2">⚠️ Why this was flagged:</p>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      {analysis.threatReasons.map((reason, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-destructive mt-0.5">•</span>
                          {reason}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
              
              {detailedData && <DetailedReport data={detailedData} />}
              {detailedError && (
                <div className="max-w-2xl mx-auto p-4 rounded-lg border border-destructive/50 bg-destructive/10 text-center">
                  <p className="text-sm font-medium text-destructive">⚠️ {detailedError}</p>
                </div>
              )}

              <div className="text-center">
                <button
                  onClick={handleReset}
                  className="text-primary hover:text-primary/80 underline underline-offset-4 transition-colors"
                >
                  Analyze another URL
                </button>
              </div>
            </div>
          )}
        </div>
      </section>

      <Features />
      <HowItWorks />
      <Footer />
    </div>
  );
};

export default Index;
