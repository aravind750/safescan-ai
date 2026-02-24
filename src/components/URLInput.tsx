import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search, QrCode, Link2 } from "lucide-react";
import jsQR from "jsqr";

interface URLInputProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
}

export const URLInput = ({ onAnalyze, isLoading }: URLInputProps) => {
  const [url, setUrl] = useState("");
  const [inputType, setInputType] = useState<"url" | "qr">("url");
  const [qrError, setQrError] = useState<string | null>(null);
  const [qrFileName, setQrFileName] = useState<string | null>(null);

  const decodeQR = (file: File) => {
    setQrError(null);
    setQrFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext("2d");
        if (!ctx) return;
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code?.data) {
          setUrl(code.data);
          setQrError(null);
        } else {
          setQrError("Could not detect a QR code in this image. Please try another image.");
          setUrl("");
        }
      };
      img.src = reader.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto space-y-4">
      <div className="flex gap-2 justify-center">
        <Button
          variant={inputType === "url" ? "cyber" : "cyberOutline"}
          size="sm"
          onClick={() => setInputType("url")}
          className="gap-2"
        >
          <Link2 className="w-4 h-4" />
          URL
        </Button>
        <Button
          variant={inputType === "qr" ? "cyber" : "cyberOutline"}
          size="sm"
          onClick={() => setInputType("qr")}
          className="gap-2"
        >
          <QrCode className="w-4 h-4" />
          QR Code
        </Button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {inputType === "url" ? (
          <div className="relative">
            <Input
              type="url"
              placeholder="Enter URL to analyze (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="h-14 pl-12 pr-4 text-lg bg-card border-border focus:border-primary focus:ring-primary/30 rounded-xl"
            />
            <Link2 className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
          </div>
        ) : (
          <div className="border-2 border-dashed border-border rounded-xl p-8 text-center hover:border-primary/50 transition-colors cursor-pointer bg-card/50">
            <QrCode className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
            {qrFileName ? (
              <p className="text-sm text-primary mb-2">Uploaded: {qrFileName}</p>
            ) : (
              <p className="text-muted-foreground mb-2">
                Drag & drop a QR code image or click to upload
              </p>
            )}
            {qrError && <p className="text-sm text-dangerous mb-2">{qrError}</p>}
            {url && inputType === "qr" && (
              <p className="text-sm text-safe mb-2 font-mono truncate">Decoded: {url}</p>
            )}
            <input
              type="file"
              accept="image/*"
              className="hidden"
              id="qr-upload"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) decodeQR(file);
              }}
            />
            <label htmlFor="qr-upload">
              <Button variant="cyberOutline" size="sm" asChild>
                <span>Choose File</span>
              </Button>
            </label>
          </div>
        )}

        <Button
          type="submit"
          variant="cyber"
          size="xl"
          className="w-full"
          disabled={!url.trim() || isLoading}
        >
          {isLoading ? (
            <>
              <div className="w-5 h-5 border-2 border-primary-foreground/30 border-t-primary-foreground rounded-full animate-spin" />
              Analyzing...
            </>
          ) : (
            <>
              <Search className="w-5 h-5" />
              Analyze Security
            </>
          )}
        </Button>
      </form>
    </div>
  );
};
