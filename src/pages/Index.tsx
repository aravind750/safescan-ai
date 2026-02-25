import { useState } from "react";
import { Header } from "@/components/Header";
import { URLInput } from "@/components/URLInput";
import { AnalysisResult, generateAnalysis, ThreatLevel } from "@/components/AnalysisResult";
import { DetailedReport, UrlAnalysisData } from "@/components/DetailedReport";
import { Features } from "@/components/Features";
import { HowItWorks } from "@/components/HowItWorks";
import { Footer } from "@/components/Footer";
import { ShieldIcon } from "@/components/ShieldIcon";

interface AnalysisState {
  url: string;
  threatLevel: ThreatLevel;
  features: any[];
  score: number;
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

    // Run both: local heuristic analysis + backend deep analysis in parallel
    const localAnalysis = generateAnalysis(url);

    // Call edge function for detailed analysis
    let deepData: UrlAnalysisData | null = null;
    try {
      const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID;
      const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
      
      if (projectId && anonKey) {
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
          deepData = resData;
        } else {
          setDetailedError(resData.error || 'Deep analysis failed');
        }
      }
    } catch (e) {
      console.error('Deep analysis error:', e);
      setDetailedError('Could not connect to analysis server');
    }

    setAnalysis({ url, ...localAnalysis });
    setDetailedData(deepData);
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
              Protect yourself from phishing, malware, and fraud. Our ML-powered system analyzes URLs and QR codes in real-time to keep you safe online.
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
              
              {/* Detailed Report */}
              {detailedData && <DetailedReport data={detailedData} />}
              {detailedError && (
                <p className="text-center text-sm text-muted-foreground">
                  Detailed analysis unavailable: {detailedError}
                </p>
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
