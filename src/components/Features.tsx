import { Card } from "@/components/ui/card";
import { Brain, Shield, Zap, Eye, Database, Bell } from "lucide-react";

const features = [
  {
    icon: <Brain className="w-8 h-8" />,
    title: "ML-Powered Detection",
    description: "Advanced machine learning models trained on millions of malicious URLs to identify threats in real-time.",
  },
  {
    icon: <Shield className="w-8 h-8" />,
    title: "Multi-Layer Analysis",
    description: "Checks SSL certificates, domain reputation, redirect patterns, and content fingerprints.",
  },
  {
    icon: <Zap className="w-8 h-8" />,
    title: "Real-Time Results",
    description: "Get instant threat classification with detailed risk reports in seconds.",
  },
  {
    icon: <Eye className="w-8 h-8" />,
    title: "QR Code Scanning",
    description: "Decode and analyze QR codes to reveal hidden URLs before you scan them.",
  },
  {
    icon: <Database className="w-8 h-8" />,
    title: "Threat Database",
    description: "Continuously updated database of known phishing sites and malicious domains.",
  },
  {
    icon: <Bell className="w-8 h-8" />,
    title: "Smart Alerts",
    description: "Clear visual indicators showing Safe, Suspicious, or Dangerous status.",
  },
];

export const Features = () => {
  return (
    <section id="features" className="py-20 px-4">
      <div className="container mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            Powered by <span className="text-gradient">Machine Learning</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Deep Secure uses advanced AI to analyze URLs and QR codes, protecting you from phishing, malware, and fraud.
          </p>
        </div>
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => (
            <Card
              key={index}
              className="p-6 bg-card border-border hover:border-primary/50 transition-all duration-300 hover:shadow-lg hover:shadow-primary/10 group"
            >
              <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-4 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                {feature.icon}
              </div>
              <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
              <p className="text-muted-foreground text-sm">{feature.description}</p>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
};
