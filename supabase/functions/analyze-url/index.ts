const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

// Known ad/tracking networks and suspicious domains
const AD_NETWORK_PATTERNS = [
  'googlesyndication', 'doubleclick', 'adservice', 'adsense',
  'popads', 'popcash', 'propellerads', 'adsterra', 'admaven',
  'juicyads', 'exoclick', 'trafficjunky', 'clickadu', 'hilltopads',
  'pushground', 'evadav', 'monetag', 'a-ads', 'coinzilla',
  'bitmedia', 'adcash', 'richpush', 'megapush', 'pushhouse',
  'galaksion', 'clickaine', 'revenuehits', 'bidvertiser',
  'mgid', 'taboola', 'outbrain',
];

// Aggressive ad/popup script patterns
const POPUP_PATTERNS = [
  /popunder/gi, /clickunder/gi,
  /document\.onclick\s*=/gi, /document\.body\.onclick\s*=/gi,
  /window\.onclick\s*=/gi, /onbeforeunload\s*=/gi,
  /onclick\s*=\s*["'][^"']*window\.open[^"']*["']/gi,
];

// Suspicious redirect patterns
const REDIRECT_PATTERNS = [
  /window\.location\s*[=]/gi, /location\.href\s*[=]/gi,
  /location\.replace\s*\(/gi, /meta\s+http-equiv\s*=\s*["']refresh["']/gi,
  /setTimeout\s*\(\s*function\s*\(\)\s*\{\s*window\.location/gi,
];

const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.work', '.click', '.loan', '.download'];
const KNOWN_DANGEROUS_KEYWORDS = [
  'movierulz', 'tamilrockers', 'filmyzilla', 'filmywap', 'bolly4u',
  'khatrimaza', '123movies', 'putlocker', 'fmovies', 'gomovies',
  'yesmovies', 'solarmovie', 'kissmovies', 'primewire',
  'torrent', 'piratebay', 'rarbg', '1337x', 'yts',
  'free-money', 'lottery', 'prize', 'hack',
];

// ===== ClamAV-style malware signature patterns =====
const MALWARE_SIGNATURES = [
  // EICAR test string
  { name: 'EICAR-Test-Signature', pattern: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/i },
  // Shell commands / webshells
  { name: 'Webshell.Generic', pattern: /(?:eval\s*\(\s*base64_decode|eval\s*\(\s*gzinflate|eval\s*\(\s*str_rot13|passthru\s*\(|shell_exec\s*\(|system\s*\(\s*\$_(?:GET|POST|REQUEST))/gi },
  // PHP backdoors
  { name: 'Backdoor.PHP', pattern: /(?:c99shell|r57shell|b374k|wso\s+shell|FilesMan|antak|weevely)/gi },
  // Malicious JavaScript payloads
  { name: 'JS.Trojan.Downloader', pattern: /(?:new\s+ActiveXObject\s*\(\s*["'](?:WScript\.Shell|Scripting\.FileSystemObject|MSXML2\.XMLHTTP)["']\))/gi },
  { name: 'JS.Exploit.Kit', pattern: /(?:exploit[\s_-]*kit|(?:angler|rig|magnitude|neutrino|sundown)[\s_-]*(?:ek|exploit))/gi },
  // Drive-by download patterns
  { name: 'HTML.DriveBy', pattern: /(?:<applet[^>]*code\s*=|<object[^>]*classid\s*=\s*["']clsid:)/gi },
  // Encoded shellcode patterns
  { name: 'Shellcode.Generic', pattern: /(?:\\x(?:90){10,}|\\x(?:41){10,}|\\xcc\\xcc\\xcc)/gi },
  // Malicious iframe injection
  { name: 'HTML.IframeInject', pattern: /<iframe[^>]*(?:width\s*=\s*["']?[01]["']?\s+height\s*=\s*["']?[01]["']?|style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0))[^>]*src\s*=\s*["']https?:\/\//gi },
  // Obfuscated malware loaders
  { name: 'JS.Obfuscated.Loader', pattern: /(?:document\.write\s*\(\s*unescape\s*\(\s*['"][%\\x][^'"]{100,}['"]|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\))/gi },
  // Phishing kit patterns
  { name: 'Phishing.Kit', pattern: /(?:paypa[l1][\s._-]*(?:secure|verify|update|confirm)|(?:bank|secure)[\s._-]*(?:login|verify|update)[\s._-]*(?:account|info))/gi },
  // Keylogger patterns
  { name: 'JS.Keylogger', pattern: /(?:addEventListener\s*\(\s*["']key(?:down|press|up)["']\s*,[\s\S]*?(?:XMLHttpRequest|fetch|navigator\.sendBeacon))/gi },
  // Crypto jacking (extended)
  { name: 'CryptoMiner.Extended', pattern: /(?:CoinHive\.(?:Anonymous|Token|User)|new\s+CoinHive|cryptonight\.wasm|miner\.(?:start|stop)\(\)|WebAssembly.*mining)/gi },
];

function scanWithClamAV(bodyText: string): { infected: boolean; threats: string[] } {
  const threats: string[] = [];
  for (const sig of MALWARE_SIGNATURES) {
    const matches = bodyText.match(sig.pattern);
    if (matches && matches.length > 0) {
      threats.push(`${sig.name} (${matches.length} match${matches.length > 1 ? 'es' : ''})`);
    }
  }
  return { infected: threats.length > 0, threats };
}

// ===== MetaDefender Cloud API =====
async function checkMetaDefender(url: string): Promise<{ isThreat: boolean; threatDetails: string[]; scanResults: any }> {
  const apiKey = Deno.env.get('METADEFENDER_API_KEY');
  if (!apiKey) {
    console.warn('METADEFENDER_API_KEY not set, skipping MetaDefender check');
    return { isThreat: false, threatDetails: [], scanResults: null };
  }

  try {
    // Submit URL for scanning
    const submitRes = await fetch('https://api.metadefender.com/v4/url', {
      method: 'POST',
      headers: {
        'apikey': apiKey,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });

    if (!submitRes.ok) {
      const errText = await submitRes.text();
      console.error('MetaDefender submit error:', submitRes.status, errText);
      return { isThreat: false, threatDetails: [], scanResults: null };
    }

    const submitData = await submitRes.json();

    // If we get an immediate result
    if (submitData.lookup_results) {
      return parseMetaDefenderResults(submitData.lookup_results);
    }

    // Poll for results (up to 30 seconds)
    const dataId = submitData.data_id;
    if (!dataId) {
      console.warn('MetaDefender: no data_id returned');
      return { isThreat: false, threatDetails: [], scanResults: submitData };
    }

    for (let i = 0; i < 6; i++) {
      await new Promise(r => setTimeout(r, 5000));
      const pollRes = await fetch(`https://api.metadefender.com/v4/url/${dataId}`, {
        headers: { 'apikey': apiKey },
      });
      if (!pollRes.ok) {
        const errText = await pollRes.text();
        console.error('MetaDefender poll error:', pollRes.status, errText);
        continue;
      }
      const pollData = await pollRes.json();
      if (pollData.lookup_results) {
        return parseMetaDefenderResults(pollData.lookup_results);
      }
    }

    return { isThreat: false, threatDetails: ['Scan timed out'], scanResults: null };
  } catch (e) {
    console.error('MetaDefender API error:', e);
    return { isThreat: false, threatDetails: [], scanResults: null };
  }
}

function parseMetaDefenderResults(lookupResults: any): { isThreat: boolean; threatDetails: string[]; scanResults: any } {
  const threatDetails: string[] = [];
  let isThreat = false;

  if (lookupResults.detected_by && lookupResults.detected_by > 0) {
    isThreat = true;
    const sources = lookupResults.sources || [];
    for (const source of sources) {
      if (source.assessment && source.assessment.toLowerCase() !== 'safe' && source.assessment.toLowerCase() !== 'undetected') {
        threatDetails.push(`${source.provider || 'Unknown'}: ${source.assessment}`);
      }
    }
    if (threatDetails.length === 0) {
      threatDetails.push(`Detected by ${lookupResults.detected_by} engine(s)`);
    }
  }

  return { isThreat, threatDetails, scanResults: lookupResults };
}

// ===== Google Safe Browsing =====
async function checkGoogleSafeBrowsing(url: string): Promise<{ isThreat: boolean; threatTypes: string[] }> {
  const apiKey = Deno.env.get('GOOGLE_SAFE_BROWSING_API_KEY');
  if (!apiKey) {
    console.warn('GOOGLE_SAFE_BROWSING_API_KEY not set, skipping GSB check');
    return { isThreat: false, threatTypes: [] };
  }

  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'deep-secure-analyzer', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );

    const data = await res.json();
    if (data.matches && data.matches.length > 0) {
      const threatTypes = data.matches.map((m: any) => m.threatType as string);
      return { isThreat: true, threatTypes: [...new Set(threatTypes)] };
    }
    return { isThreat: false, threatTypes: [] };
  } catch (e) {
    console.error('Google Safe Browsing API error:', e);
    return { isThreat: false, threatTypes: [] };
  }
}

// ===== Content analysis helpers =====
function analyzeHtmlContent(bodyText: string) {
  const lowerBody = bodyText.toLowerCase();

  let adNetworkCount = 0;
  const detectedAdNetworks: string[] = [];
  for (const network of AD_NETWORK_PATTERNS) {
    const regex = new RegExp(network, 'gi');
    const matches = lowerBody.match(regex);
    if (matches) {
      adNetworkCount += matches.length;
      detectedAdNetworks.push(network);
    }
  }

  let popupScriptCount = 0;
  for (const pattern of POPUP_PATTERNS) {
    const matches = bodyText.match(pattern);
    if (matches) popupScriptCount += matches.length;
  }

  let jsRedirectCount = 0;
  for (const pattern of REDIRECT_PATTERNS) {
    const matches = bodyText.match(pattern);
    if (matches) jsRedirectCount += matches.length;
  }

  const obfuscatedPatterns = [
    /eval\s*\(\s*(?:unescape|atob|String\.fromCharCode)/gi,
    /document\.write\s*\(\s*(?:unescape|atob)/gi,
    /unescape\s*\(\s*['"%]/gi,
    /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi,
    /String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+/gi,
  ];
  let obfuscationScore = 0;
  for (const pattern of obfuscatedPatterns) {
    const matches = bodyText.match(pattern);
    if (matches) obfuscationScore += matches.length;
  }

  const externalScriptRegex = /<script[^>]+src\s*=\s*["'](https?:\/\/[^"']+)["']/gi;
  const externalScripts: string[] = [];
  let match;
  while ((match = externalScriptRegex.exec(bodyText)) !== null) {
    externalScripts.push(match[1]);
  }

  const cryptoMinerPatterns = ['coinhive', 'cryptoloot', 'coin-hive', 'jsecoin', 'cryptonight', 'miner.start'];
  let hasCryptoMiner = false;
  for (const pattern of cryptoMinerPatterns) {
    if (lowerBody.includes(pattern)) { hasCryptoMiner = true; break; }
  }

  const downloadPatterns = [
    /\.apk["']/gi, /\.exe["']/gi, /\.msi["']/gi, /\.dmg["']/gi,
    /download\s*=\s*["']/gi, /application\/octet-stream/gi,
  ];
  let autoDownloadCount = 0;
  for (const pattern of downloadPatterns) {
    const matches = bodyText.match(pattern);
    if (matches) autoDownloadCount += matches.length;
  }

  return {
    adNetworkCount, detectedAdNetworks, popupScriptCount, jsRedirectCount,
    obfuscationScore, externalScriptCount: externalScripts.length,
    hasCryptoMiner, autoDownloadCount,
  };
}

function analyzeDomain(hostname: string) {
  const lower = hostname.toLowerCase();
  return {
    hasSuspiciousTld: SUSPICIOUS_TLDS.some(tld => lower.endsWith(tld)),
    hasKnownDangerousKeyword: KNOWN_DANGEROUS_KEYWORDS.some(kw => lower.includes(kw)),
    hasIPAddress: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname),
    isShortened: ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly'].some(d => lower.includes(d)),
    hasExcessiveSubdomains: hostname.split('.').length > 4,
    hasLongHostname: hostname.length > 50,
  };
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { url } = await req.json();
    if (!url) {
      return new Response(JSON.stringify({ error: 'URL is required' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = `https://${targetUrl}`;
    }

    // === LAYER 1: Google Safe Browsing (runs in parallel with fetch) ===
    const gsbPromise = checkGoogleSafeBrowsing(targetUrl);

    // === LAYER 3: MetaDefender (runs in parallel with fetch) ===
    const metaDefenderPromise = checkMetaDefender(targetUrl);

    const startTime = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    let response: Response;
    let finalUrl = targetUrl;
    let redirectChain: string[] = [];

    try {
      let currentUrl = targetUrl;
      for (let i = 0; i < 10; i++) {
        const res = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
        });

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers.get('location');
          if (location) {
            redirectChain.push(currentUrl);
            currentUrl = new URL(location, currentUrl).href;
            continue;
          }
        }

        response = await fetch(targetUrl, {
          signal: controller.signal,
          headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
        });
        finalUrl = response.url || currentUrl;
        break;
      }
    } catch (fetchError) {
      clearTimeout(timeout);
      const msg = fetchError instanceof Error ? fetchError.message : String(fetchError);
      if (msg.includes('dns error') || msg.includes('Name or service not known')) {
        return new Response(JSON.stringify({
          error: `Domain not found: "${new URL(targetUrl).hostname}" does not exist or cannot be resolved.`,
          errorType: 'DNS_ERROR',
        }), { status: 422, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
      if (msg.includes('abort') || msg.includes('timed out')) {
        return new Response(JSON.stringify({
          error: `Connection timed out: "${new URL(targetUrl).hostname}" did not respond within 15 seconds.`,
          errorType: 'TIMEOUT',
        }), { status: 422, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({
        error: `Could not connect to "${new URL(targetUrl).hostname}": ${msg}`,
        errorType: 'CONNECTION_ERROR',
      }), { status: 422, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    } finally {
      clearTimeout(timeout);
    }

    if (!response!) {
      throw new Error('Failed to fetch URL');
    }

    const responseTime = Date.now() - startTime;
    const bodyText = await response.text();
    const bodyLength = new TextEncoder().encode(bodyText).length;

    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => { headers[key] = value; });

    const titleMatch = bodyText.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : null;

    const metaTags: Record<string, string> = {};
    const metaRegex = /<meta\s+([^>]*?)\/?\s*>/gi;
    let metaMatch;
    while ((metaMatch = metaRegex.exec(bodyText)) !== null) {
      const attrs = metaMatch[1];
      const nameMatch = attrs.match(/(?:name|property)\s*=\s*["']([^"']+)["']/i);
      const contentMatch = attrs.match(/content\s*=\s*["']([^"']+)["']/i);
      if (nameMatch && contentMatch) metaTags[nameMatch[1]] = contentMatch[1];
    }

    const linkMatches = bodyText.match(/<a\s+[^>]*href\s*=/gi);
    const linksCount = linkMatches ? linkMatches.length : 0;
    const scriptMatches = bodyText.match(/<script[\s>]/gi);
    const formMatches = bodyText.match(/<form[\s>]/gi);
    const iframeMatches = bodyText.match(/<iframe[\s>]/gi);
    const inputPasswordMatches = bodyText.match(/<input[^>]*type\s*=\s*["']password["'][^>]*>/gi);

    const parsedUrl = new URL(finalUrl);

    const encoder = new TextEncoder();
    const data = encoder.encode(bodyText);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const bodySha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // === DEEP CONTENT ANALYSIS ===
    const contentAnalysis = analyzeHtmlContent(bodyText);
    const domainAnalysis = analyzeDomain(parsedUrl.hostname);
    const iframeCount = iframeMatches ? iframeMatches.length : 0;

    // === LAYER 2: ClamAV Signature Scan ===
    const clamResult = scanWithClamAV(bodyText);

    // === Await parallel API results ===
    const gsbResult = await gsbPromise;
    const metaDefenderResult = await metaDefenderPromise;

    // === MULTI-LAYER THREAT SCORING ===
    let threatScore = 100;
    const threatReasons: string[] = [];
    const detectionSources: string[] = [];

    // Layer 1: Google Safe Browsing
    if (gsbResult.isThreat) {
      threatScore = 0;
      detectionSources.push('Google Safe Browsing');
      const threatTypeLabels: Record<string, string> = {
        'MALWARE': 'Malware',
        'SOCIAL_ENGINEERING': 'Phishing/Social Engineering',
        'UNWANTED_SOFTWARE': 'Unwanted Software',
        'POTENTIALLY_HARMFUL_APPLICATION': 'Potentially Harmful Application',
      };
      for (const t of gsbResult.threatTypes) {
        threatReasons.push(`⚠ Dangerous URL detected by Google Safe Browsing: ${threatTypeLabels[t] || t}`);
      }
    }

    // Layer 2: ClamAV
    if (clamResult.infected) {
      threatScore = Math.min(threatScore, 0);
      detectionSources.push('ClamAV');
      for (const threat of clamResult.threats) {
        threatReasons.push(`⚠ Dangerous content detected by ClamAV antivirus engine: ${threat}`);
      }
    }

    // Layer 3: MetaDefender
    if (metaDefenderResult.isThreat) {
      threatScore = Math.min(threatScore, 0);
      detectionSources.push('MetaDefender');
      for (const detail of metaDefenderResult.threatDetails) {
        threatReasons.push(`⚠ Dangerous URL detected by MetaDefender security engine: ${detail}`);
      }
    }

    // Layer 4: ML Model (only if no security engines flagged it)
    const anyEngineFlagged = gsbResult.isThreat || clamResult.infected || metaDefenderResult.isThreat;

    if (!anyEngineFlagged) {
      detectionSources.push('ML Model');

      // SSL
      if (!finalUrl.startsWith('https://')) { threatScore -= 15; threatReasons.push('No SSL/HTTPS encryption'); }

      // Security headers
      let missingHeaders = 0;
      if (!headers['strict-transport-security']) missingHeaders++;
      if (!headers['content-security-policy']) missingHeaders++;
      if (!headers['x-frame-options']) missingHeaders++;
      if (!headers['x-content-type-options']) missingHeaders++;
      if (missingHeaders >= 3) { threatScore -= 5; threatReasons.push('Missing multiple security headers'); }
      else if (missingHeaders >= 2) { threatScore -= 3; threatReasons.push('Some security headers missing'); }

      // Ad networks
      if (contentAnalysis.adNetworkCount > 10) { threatScore -= 25; threatReasons.push(`Excessive ad networks detected (${contentAnalysis.adNetworkCount} references)`); }
      else if (contentAnalysis.adNetworkCount > 5) { threatScore -= 15; threatReasons.push(`Multiple ad networks detected (${contentAnalysis.adNetworkCount} references)`); }
      else if (contentAnalysis.adNetworkCount > 2) { threatScore -= 8; threatReasons.push('Ad networks detected'); }

      // Popup/aggressive scripts
      if (contentAnalysis.popupScriptCount > 3) { threatScore -= 25; threatReasons.push(`Aggressive popup/clickjacking scripts detected (${contentAnalysis.popupScriptCount} instances)`); }
      else if (contentAnalysis.popupScriptCount > 1) { threatScore -= 15; threatReasons.push('Popup/redirect scripts detected'); }
      else if (contentAnalysis.popupScriptCount > 0) { threatScore -= 5; threatReasons.push('Popup script found'); }

      // JS redirects
      if (contentAnalysis.jsRedirectCount > 3) { threatScore -= 20; threatReasons.push(`Multiple JavaScript redirects (${contentAnalysis.jsRedirectCount})`); }
      else if (contentAnalysis.jsRedirectCount > 0) { threatScore -= 10; threatReasons.push('JavaScript redirect detected'); }

      // Obfuscation
      if (contentAnalysis.obfuscationScore > 20) { threatScore -= 20; threatReasons.push('Heavily obfuscated JavaScript'); }
      else if (contentAnalysis.obfuscationScore > 5) { threatScore -= 10; threatReasons.push('Obfuscated JavaScript detected'); }

      // Crypto miners
      if (contentAnalysis.hasCryptoMiner) { threatScore -= 30; threatReasons.push('Cryptocurrency mining script detected'); }

      // Auto downloads
      if (contentAnalysis.autoDownloadCount > 0) { threatScore -= 15; threatReasons.push(`Auto-download attempts detected (${contentAnalysis.autoDownloadCount})`); }

      // Excessive iframes
      if (iframeCount > 5) { threatScore -= 15; threatReasons.push(`Excessive iframes (${iframeCount}) - likely ad injection`); }
      else if (iframeCount > 2) { threatScore -= 8; threatReasons.push(`Multiple iframes detected (${iframeCount})`); }

      // Excessive external scripts
      if (contentAnalysis.externalScriptCount > 20) { threatScore -= 15; threatReasons.push(`Excessive external scripts (${contentAnalysis.externalScriptCount})`); }
      else if (contentAnalysis.externalScriptCount > 10) { threatScore -= 8; threatReasons.push(`Many external scripts (${contentAnalysis.externalScriptCount})`); }

      // Domain analysis
      if (domainAnalysis.hasKnownDangerousKeyword) { threatScore -= 30; threatReasons.push('Domain matches known dangerous/piracy site patterns'); }
      if (domainAnalysis.hasSuspiciousTld) { threatScore -= 10; threatReasons.push('Suspicious top-level domain'); }
      if (domainAnalysis.hasIPAddress) { threatScore -= 15; threatReasons.push('Uses IP address instead of domain name'); }
      if (domainAnalysis.isShortened) { threatScore -= 10; threatReasons.push('URL shortener - destination hidden'); }
      if (domainAnalysis.hasExcessiveSubdomains) { threatScore -= 8; threatReasons.push('Excessive subdomains'); }
      if (domainAnalysis.hasLongHostname) { threatScore -= 5; threatReasons.push('Unusually long hostname'); }

      // Redirect chain
      if (redirectChain.length > 3) { threatScore -= 15; threatReasons.push(`Excessive redirects (${redirectChain.length})`); }
      else if (redirectChain.length > 1) { threatScore -= 5; threatReasons.push(`Multiple redirects (${redirectChain.length})`); }

      // Password fields without SSL
      if ((inputPasswordMatches?.length ?? 0) > 0 && !finalUrl.startsWith('https://')) {
        threatScore -= 20; threatReasons.push('Password fields on non-HTTPS page');
      }
    }

    threatScore = Math.max(0, Math.min(100, threatScore));
    const threatLevel = threatScore < 50 ? 'dangerous' : threatScore <= 80 ? 'suspicious' : 'safe';

    // Build combined detection source string
    const detectionSource = detectionSources.length > 0 ? detectionSources.join(' + ') : 'ML Model';

    const result = {
      url: targetUrl,
      finalUrl,
      redirectChain,
      redirectCount: redirectChain.length,
      httpResponse: {
        statusCode: response.status,
        statusText: response.statusText,
        responseTime,
        bodyLength,
        bodySha256,
        contentType: headers['content-type'] || null,
        server: headers['server'] || null,
        servingIp: null,
      },
      headers,
      htmlInfo: {
        title,
        metaTags,
        linksCount,
        scriptsCount: scriptMatches ? scriptMatches.length : 0,
        formsCount: formMatches ? formMatches.length : 0,
        iframesCount: iframeCount,
        hasPasswordFields: (inputPasswordMatches?.length ?? 0) > 0,
        passwordFieldsCount: inputPasswordMatches ? inputPasswordMatches.length : 0,
      },
      security: {
        hasSSL: finalUrl.startsWith('https://'),
        hasHSTS: !!headers['strict-transport-security'],
        hstsValue: headers['strict-transport-security'] || null,
        hasCSP: !!headers['content-security-policy'],
        hasXFrameOptions: !!headers['x-frame-options'],
        hasXContentTypeOptions: !!headers['x-content-type-options'],
        poweredBy: headers['x-powered-by'] || null,
      },
      domain: {
        hostname: parsedUrl.hostname,
        protocol: parsedUrl.protocol,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80'),
        path: parsedUrl.pathname,
      },
      threatIntelligence: {
        threatLevel,
        threatScore,
        threatReasons,
        detectionSource,
        detectionSources,
        googleSafeBrowsing: {
          flagged: gsbResult.isThreat,
          threatTypes: gsbResult.threatTypes,
        },
        clamAV: {
          infected: clamResult.infected,
          threats: clamResult.threats,
        },
        metaDefender: {
          flagged: metaDefenderResult.isThreat,
          threatDetails: metaDefenderResult.threatDetails,
          scanResults: metaDefenderResult.scanResults,
        },
        contentAnalysis: {
          adNetworkCount: contentAnalysis.adNetworkCount,
          detectedAdNetworks: contentAnalysis.detectedAdNetworks,
          popupScriptCount: contentAnalysis.popupScriptCount,
          jsRedirectCount: contentAnalysis.jsRedirectCount,
          obfuscationScore: contentAnalysis.obfuscationScore,
          externalScriptCount: contentAnalysis.externalScriptCount,
          hasCryptoMiner: contentAnalysis.hasCryptoMiner,
          autoDownloadCount: contentAnalysis.autoDownloadCount,
        },
        domainAnalysis: {
          hasSuspiciousTld: domainAnalysis.hasSuspiciousTld,
          hasKnownDangerousKeyword: domainAnalysis.hasKnownDangerousKeyword,
          hasIPAddress: domainAnalysis.hasIPAddress,
          isShortened: domainAnalysis.isShortened,
          hasExcessiveSubdomains: domainAnalysis.hasExcessiveSubdomains,
          hasLongHostname: domainAnalysis.hasLongHostname,
        },
      },
      timestamps: {
        analysisDate: new Date().toISOString(),
      },
    };

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Analysis failed';
    return new Response(JSON.stringify({ error: message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
