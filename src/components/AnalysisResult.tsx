import { ShieldIcon } from "./ShieldIcon";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Globe, 
  Lock, 
  Clock, 
  ExternalLink,
  Download,
  Ban,
  Megaphone
} from "lucide-react";

export type ThreatLevel = "safe" | "suspicious" | "dangerous";

interface AnalysisFeature {
  name: string;
  status: "pass" | "warning" | "fail";
  description: string;
  icon: React.ReactNode;
}

interface AnalysisResultProps {
  url: string;
  threatLevel: ThreatLevel;
  features: AnalysisFeature[];
  score: number;
}

export const AnalysisResult = ({ url, threatLevel, features, score }: AnalysisResultProps) => {
  const statusConfig = {
    safe: {
      title: "Safe",
      description: "This URL appears to be legitimate and safe to visit.",
      bgClass: "bg-safe/10 border-safe/30",
      textClass: "text-safe",
    },
    suspicious: {
      title: "Suspicious",
      description: "This URL has some concerning characteristics. Proceed with caution.",
      bgClass: "bg-suspicious/10 border-suspicious/30",
      textClass: "text-suspicious",
    },
    dangerous: {
      title: "Dangerous",
      description: "This URL is likely malicious. Do not visit this website.",
      bgClass: "bg-dangerous/10 border-dangerous/30",
      textClass: "text-dangerous",
    },
  };

  const config = statusConfig[threatLevel];

  const getStatusIcon = (status: "pass" | "warning" | "fail") => {
    switch (status) {
      case "pass":
        return <CheckCircle2 className="w-5 h-5 text-safe" />;
      case "warning":
        return <AlertTriangle className="w-5 h-5 text-suspicious" />;
      case "fail":
        return <XCircle className="w-5 h-5 text-dangerous" />;
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      {/* Main Result Card */}
      <Card className={`p-8 ${config.bgClass} border-2`}>
        <div className="flex flex-col md:flex-row items-center gap-6">
          <div className="animate-float">
            <ShieldIcon status={threatLevel} className="w-24 h-24" />
          </div>
          <div className="flex-1 text-center md:text-left">
            <div className="flex items-center justify-center md:justify-start gap-3 mb-2">
              <h2 className={`text-3xl font-bold ${config.textClass}`}>
                {config.title}
              </h2>
              <Badge variant="outline" className={`${config.textClass} border-current`}>
                Score: {score}/100
              </Badge>
            </div>
            <p className="text-muted-foreground mb-3">{config.description}</p>
            <div className="flex items-center justify-center md:justify-start gap-2 text-sm text-muted-foreground bg-background/50 rounded-lg px-3 py-2">
              <Globe className="w-4 h-4" />
              <span className="truncate max-w-md font-mono">{url}</span>
            </div>
          </div>
        </div>
      </Card>

      {/* Feature Analysis */}
      <Card className="p-6 bg-card border-border">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Lock className="w-5 h-5 text-primary" />
          Security Analysis
        </h3>
        <div className="grid gap-3">
          {features.map((feature, index) => (
            <div
              key={index}
              className="flex items-center gap-4 p-4 rounded-lg bg-background/50 border border-border/50 hover:border-primary/30 transition-colors"
            >
              <div className="text-muted-foreground">{feature.icon}</div>
              {getStatusIcon(feature.status)}
              <div className="flex-1">
                <p className="font-medium">{feature.name}</p>
                <p className="text-sm text-muted-foreground">{feature.description}</p>
              </div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};

// Helper to generate mock analysis
export const generateAnalysis = (url: string): { threatLevel: ThreatLevel; features: AnalysisFeature[]; score: number } => {
  // Simulate ML analysis based on URL patterns
  const lowerUrl = url.toLowerCase();
  
  const isSuspicious = 
    lowerUrl.includes("login") || 
    lowerUrl.includes("verify") ||
    lowerUrl.includes("secure") ||
    lowerUrl.includes("account") ||
    lowerUrl.length > 100;

  const isDangerous = 
    lowerUrl.includes("free-money") ||
    lowerUrl.includes("lottery") ||
    lowerUrl.includes("prize") ||
    lowerUrl.includes("hack") ||
    lowerUrl.includes(".tk") ||
    lowerUrl.includes(".ml") ||
    /\d{4,}/.test(lowerUrl);

  const hasSSL = url.startsWith("https://");
  const hasIPAddress = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
  const hasSuspiciousChars = /[@!#$%^&*()=+\[\]{}|\\<>]/.test(url);
  const isShortened = lowerUrl.includes("bit.ly") || lowerUrl.includes("tinyurl") || lowerUrl.includes("t.co");

  const features: AnalysisFeature[] = [
    {
      name: "SSL Certificate",
      status: hasSSL ? "pass" : "warning",
      description: hasSSL ? "Website uses HTTPS encryption" : "Website does not use HTTPS",
      icon: <Lock className="w-5 h-5" />,
    },
    {
      name: "Domain Reputation",
      status: isDangerous ? "fail" : isSuspicious ? "warning" : "pass",
      description: isDangerous ? "Domain flagged in threat databases" : isSuspicious ? "Domain has limited history" : "Domain has good reputation",
      icon: <Globe className="w-5 h-5" />,
    },
    {
      name: "Redirect Behavior",
      status: isShortened ? "warning" : "pass",
      description: isShortened ? "URL uses link shortener (may redirect)" : "Direct link with no hidden redirects",
      icon: <ExternalLink className="w-5 h-5" />,
    },
    {
      name: "Auto-Download Check",
      status: isDangerous ? "fail" : "pass",
      description: isDangerous ? "Page may attempt automatic downloads" : "No automatic downloads detected",
      icon: <Download className="w-5 h-5" />,
    },
    {
      name: "Suspicious Ads Detection",
      status: isDangerous ? "fail" : isSuspicious ? "warning" : "pass",
      description: isDangerous ? "Contains betting/fraud advertisement patterns" : isSuspicious ? "May contain promotional content" : "No suspicious ads detected",
      icon: <Megaphone className="w-5 h-5" />,
    },
    {
      name: "Banned Domain Check",
      status: hasIPAddress ? "fail" : "pass",
      description: hasIPAddress ? "Uses IP address instead of domain name" : "Domain is not in blocklist",
      icon: <Ban className="w-5 h-5" />,
    },
  ];

  let score = 100;
  features.forEach(f => {
    if (f.status === "warning") score -= 10;
    if (f.status === "fail") score -= 25;
  });
  score = Math.max(0, score);

  const threatLevel: ThreatLevel = 
    isDangerous || score < 40 ? "dangerous" :
    isSuspicious || score < 70 ? "suspicious" : "safe";

  return { threatLevel, features, score };
};
