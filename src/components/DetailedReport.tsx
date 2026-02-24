import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Globe, Shield, FileText, Server, Clock, Link2, 
  Lock, Unlock, CheckCircle2, XCircle, ExternalLink,
  Code, AlertTriangle
} from "lucide-react";

export interface UrlAnalysisData {
  url: string;
  finalUrl: string;
  redirectChain: string[];
  redirectCount: number;
  httpResponse: {
    statusCode: number;
    statusText: string;
    responseTime: number;
    bodyLength: number;
    bodySha256: string;
    contentType: string | null;
    server: string | null;
    servingIp: string | null;
  };
  headers: Record<string, string>;
  htmlInfo: {
    title: string | null;
    metaTags: Record<string, string>;
    linksCount: number;
    scriptsCount: number;
    formsCount: number;
    iframesCount: number;
    hasPasswordFields: boolean;
    passwordFieldsCount: number;
  };
  security: {
    hasSSL: boolean;
    hasHSTS: boolean;
    hstsValue: string | null;
    hasCSP: boolean;
    hasXFrameOptions: boolean;
    hasXContentTypeOptions: boolean;
    poweredBy: string | null;
  };
  domain: {
    hostname: string;
    protocol: string;
    port: string;
    path: string;
  };
  timestamps: {
    analysisDate: string;
  };
}

interface DetailedReportProps {
  data: UrlAnalysisData;
}

const formatBytes = (bytes: number) => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

const SecurityBadge = ({ secure, label }: { secure: boolean; label: string }) => (
  <div className="flex items-center gap-2">
    {secure ? (
      <CheckCircle2 className="w-4 h-4 text-safe" />
    ) : (
      <XCircle className="w-4 h-4 text-dangerous" />
    )}
    <span className="text-sm">{label}</span>
  </div>
);

export const DetailedReport = ({ data }: DetailedReportProps) => {
  const headerEntries = Object.entries(data.headers);
  const metaEntries = Object.entries(data.htmlInfo.metaTags);

  return (
    <div className="w-full max-w-3xl mx-auto mt-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="w-full grid grid-cols-5 bg-card border border-border">
          <TabsTrigger value="overview" className="gap-1.5 text-xs sm:text-sm">
            <Globe className="w-3.5 h-3.5" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="headers" className="gap-1.5 text-xs sm:text-sm">
            <Server className="w-3.5 h-3.5" />
            Headers
          </TabsTrigger>
          <TabsTrigger value="html" className="gap-1.5 text-xs sm:text-sm">
            <Code className="w-3.5 h-3.5" />
            HTML
          </TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5 text-xs sm:text-sm">
            <Shield className="w-3.5 h-3.5" />
            Security
          </TabsTrigger>
          <TabsTrigger value="redirects" className="gap-1.5 text-xs sm:text-sm">
            <ExternalLink className="w-3.5 h-3.5" />
            Redirects
          </TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview">
          <Card className="p-6 bg-card border-border space-y-4">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <Globe className="w-5 h-5 text-primary" />
              HTTP Response
            </h3>
            <Table>
              <TableBody>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground w-1/3">Final URL</TableCell>
                  <TableCell className="font-mono text-xs break-all">{data.finalUrl}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Status Code</TableCell>
                  <TableCell>
                    <Badge variant={data.httpResponse.statusCode === 200 ? "default" : "destructive"}>
                      {data.httpResponse.statusCode} {data.httpResponse.statusText}
                    </Badge>
                  </TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Content Type</TableCell>
                  <TableCell className="font-mono text-xs">{data.httpResponse.contentType || "N/A"}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Server</TableCell>
                  <TableCell>{data.httpResponse.server || "N/A"}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Response Time</TableCell>
                  <TableCell>{data.httpResponse.responseTime} ms</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Body Length</TableCell>
                  <TableCell>{formatBytes(data.httpResponse.bodyLength)}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Body SHA-256</TableCell>
                  <TableCell className="font-mono text-xs break-all">{data.httpResponse.bodySha256}</TableCell>
                </TableRow>
                <TableRow>
                  <TableCell className="font-medium text-muted-foreground">Analysis Date</TableCell>
                  <TableCell>{new Date(data.timestamps.analysisDate).toLocaleString()}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        {/* Headers Tab */}
        <TabsContent value="headers">
          <Card className="p-6 bg-card border-border">
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
              <Server className="w-5 h-5 text-primary" />
              Response Headers ({headerEntries.length})
            </h3>
            <ScrollArea className="h-[400px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-1/3">Header</TableHead>
                    <TableHead>Value</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {headerEntries.map(([key, value]) => (
                    <TableRow key={key}>
                      <TableCell className="font-mono text-xs text-primary">{key}</TableCell>
                      <TableCell className="font-mono text-xs break-all">{value}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          </Card>
        </TabsContent>

        {/* HTML Info Tab */}
        <TabsContent value="html">
          <Card className="p-6 bg-card border-border space-y-6">
            <div>
              <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
                <FileText className="w-5 h-5 text-primary" />
                Page Info
              </h3>
              <Table>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground w-1/3">Title</TableCell>
                    <TableCell>{data.htmlInfo.title || "N/A"}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground">Links</TableCell>
                    <TableCell>{data.htmlInfo.linksCount}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground">Scripts</TableCell>
                    <TableCell>{data.htmlInfo.scriptsCount}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground">Forms</TableCell>
                    <TableCell>{data.htmlInfo.formsCount}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground">Iframes</TableCell>
                    <TableCell>{data.htmlInfo.iframesCount}</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium text-muted-foreground">Password Fields</TableCell>
                    <TableCell>
                      {data.htmlInfo.hasPasswordFields ? (
                        <Badge variant="destructive">{data.htmlInfo.passwordFieldsCount} found</Badge>
                      ) : (
                        <Badge variant="secondary">None</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </div>

            {metaEntries.length > 0 && (
              <div>
                <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
                  <Code className="w-5 h-5 text-primary" />
                  Meta Tags ({metaEntries.length})
                </h3>
                <ScrollArea className="h-[300px]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-1/3">Name / Property</TableHead>
                        <TableHead>Content</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {metaEntries.map(([key, value]) => (
                        <TableRow key={key}>
                          <TableCell className="font-mono text-xs text-primary">{key}</TableCell>
                          <TableCell className="text-xs break-all">{value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </div>
            )}
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security">
          <Card className="p-6 bg-card border-border space-y-4">
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
              <Shield className="w-5 h-5 text-primary" />
              Security Headers
            </h3>
            <div className="grid gap-3">
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <SecurityBadge secure={data.security.hasSSL} label="SSL/TLS (HTTPS)" />
              </div>
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <SecurityBadge secure={data.security.hasHSTS} label="HTTP Strict Transport Security (HSTS)" />
                {data.security.hstsValue && (
                  <p className="text-xs font-mono text-muted-foreground mt-1 ml-6">{data.security.hstsValue}</p>
                )}
              </div>
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <SecurityBadge secure={data.security.hasCSP} label="Content Security Policy (CSP)" />
              </div>
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <SecurityBadge secure={data.security.hasXFrameOptions} label="X-Frame-Options" />
              </div>
              <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                <SecurityBadge secure={data.security.hasXContentTypeOptions} label="X-Content-Type-Options" />
              </div>
              {data.security.poweredBy && (
                <div className="p-4 rounded-lg bg-background/50 border border-border/50">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-suspicious" />
                    <span className="text-sm">X-Powered-By exposed: <span className="font-mono text-primary">{data.security.poweredBy}</span></span>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Redirects Tab */}
        <TabsContent value="redirects">
          <Card className="p-6 bg-card border-border">
            <h3 className="text-lg font-semibold flex items-center gap-2 mb-4">
              <ExternalLink className="w-5 h-5 text-primary" />
              Redirect Chain ({data.redirectCount} redirect{data.redirectCount !== 1 ? 's' : ''})
            </h3>
            {data.redirectCount > 0 ? (
              <div className="space-y-2">
                {data.redirectChain.map((rUrl, i) => (
                  <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border border-border/50">
                    <Badge variant="outline" className="shrink-0">{i + 1}</Badge>
                    <Link2 className="w-4 h-4 text-muted-foreground shrink-0" />
                    <span className="font-mono text-xs break-all">{rUrl}</span>
                  </div>
                ))}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-safe/10 border border-safe/30">
                  <Badge className="shrink-0 bg-safe text-safe-foreground">Final</Badge>
                  <Globe className="w-4 h-4 text-safe shrink-0" />
                  <span className="font-mono text-xs break-all">{data.finalUrl}</span>
                </div>
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">No redirects detected. The URL loaded directly.</p>
            )}
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};
