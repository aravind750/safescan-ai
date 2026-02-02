import { Card } from "@/components/ui/card";
import { Link2, Cpu, CheckCircle2 } from "lucide-react";

const steps = [
  {
    icon: <Link2 className="w-10 h-10" />,
    step: "01",
    title: "Input URL or QR",
    description: "Enter a URL directly or upload a QR code image for analysis.",
  },
  {
    icon: <Cpu className="w-10 h-10" />,
    step: "02",
    title: "ML Analysis",
    description: "Our AI analyzes domain reputation, SSL, redirects, content patterns, and more.",
  },
  {
    icon: <CheckCircle2 className="w-10 h-10" />,
    step: "03",
    title: "Get Results",
    description: "Receive instant threat classification: Safe, Suspicious, or Dangerous.",
  },
];

export const HowItWorks = () => {
  return (
    <section id="how-it-works" className="py-20 px-4 bg-gradient-to-b from-background to-card">
      <div className="container mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">
            How <span className="text-gradient">It Works</span>
          </h2>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            Three simple steps to verify any URL or QR code before you click.
          </p>
        </div>
        <div className="grid md:grid-cols-3 gap-8">
          {steps.map((step, index) => (
            <div key={index} className="relative">
              {index < steps.length - 1 && (
                <div className="hidden md:block absolute top-16 left-1/2 w-full h-0.5 bg-gradient-to-r from-primary/50 to-transparent" />
              )}
              <Card className="p-8 bg-card border-border text-center relative z-10">
                <div className="text-5xl font-bold text-primary/20 absolute top-4 right-4">
                  {step.step}
                </div>
                <div className="w-20 h-20 mx-auto rounded-full bg-primary/10 flex items-center justify-center mb-6 text-primary">
                  {step.icon}
                </div>
                <h3 className="text-xl font-semibold mb-3">{step.title}</h3>
                <p className="text-muted-foreground">{step.description}</p>
              </Card>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
