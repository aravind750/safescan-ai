import { ShieldIcon } from "./ShieldIcon";
import { Github, Mail, Globe } from "lucide-react";

export const Footer = () => {
  return (
    <footer id="about" className="py-12 px-4 border-t border-border/50 bg-card/50">
      <div className="container mx-auto">
        <div className="grid md:grid-cols-3 gap-8">
          <div>
            <div className="flex items-center gap-3 mb-4">
              <ShieldIcon status="idle" className="w-8 h-8" />
              <span className="text-lg font-bold text-gradient">Deep Secure</span>
            </div>
            <p className="text-sm text-muted-foreground">
              An intelligent system designed to detect, analyze, and prevent digital threats embedded within QR codes and web URLs using Machine Learning.
            </p>
          </div>
          <div>
            <h4 className="font-semibold mb-4">Project Team</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li>Supervisor: Mr. B. Karthik</li>
              <li>M. Aravind – 23R91A05M0</li>
              <li>Mohammed Abdul Haseeb – 23R91A05L0</li>
              <li>P. Nithin – 23R91A05Q5</li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold mb-4">Institution</h4>
            <p className="text-sm text-muted-foreground mb-4">
              Teegala Krishna Reddy Engineering College<br />
              Department of Computer Science Engineering<br />
              Affiliated to JNTUH, Accredited by NBA and NAAC
            </p>
            <div className="flex gap-4">
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Globe className="w-5 h-5" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Github className="w-5 h-5" />
              </a>
              <a href="#" className="text-muted-foreground hover:text-primary transition-colors">
                <Mail className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>
        <div className="mt-8 pt-8 border-t border-border/50 text-center text-sm text-muted-foreground">
          <p>© 2024 Deep Secure. All rights reserved. | TKREC CSE Department Project</p>
        </div>
      </div>
    </footer>
  );
};
