import { ShieldIcon } from "./ShieldIcon";

export const Header = () => {
  return (
    <header className="py-6 px-4 border-b border-border/50">
      <div className="container mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldIcon status="idle" className="w-10 h-10" />
          <div>
            <h1 className="text-xl font-bold text-gradient">Deep Secure</h1>
            <p className="text-xs text-muted-foreground">QR & URL Analyzer</p>
          </div>
        </div>
        <nav className="hidden md:flex items-center gap-6 text-sm">
          <a href="#features" className="text-muted-foreground hover:text-primary transition-colors">Features</a>
          <a href="#how-it-works" className="text-muted-foreground hover:text-primary transition-colors">How It Works</a>
          <a href="#about" className="text-muted-foreground hover:text-primary transition-colors">About</a>
        </nav>
      </div>
    </header>
  );
};
