import { ShieldIcon } from "./ShieldIcon";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Globe, 
  Lock, 
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

// Analysis is now performed server-side by the edge function
