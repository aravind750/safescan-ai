const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

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

    // Ensure URL has protocol
    let targetUrl = url.trim();
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = `https://${targetUrl}`;
    }

    const startTime = Date.now();

    // Fetch the URL
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    let response: Response;
    let finalUrl = targetUrl;
    let redirectChain: string[] = [];

    try {
      // First fetch with redirect: manual to track redirects
      let currentUrl = targetUrl;
      for (let i = 0; i < 10; i++) {
        const res = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'DeepSecure-Analyzer/1.0',
          },
        });

        if (res.status >= 300 && res.status < 400) {
          const location = res.headers.get('location');
          if (location) {
            redirectChain.push(currentUrl);
            currentUrl = new URL(location, currentUrl).href;
            continue;
          }
        }

        // Final response - refetch with normal redirect to get body
        response = await fetch(targetUrl, {
          signal: controller.signal,
          headers: { 'User-Agent': 'DeepSecure-Analyzer/1.0' },
        });
        finalUrl = response.url || currentUrl;
        break;
      }
    } finally {
      clearTimeout(timeout);
    }

    if (!response!) {
      throw new Error('Failed to fetch URL');
    }

    const responseTime = Date.now() - startTime;
    const bodyText = await response.text();
    const bodyLength = new TextEncoder().encode(bodyText).length;

    // Extract headers
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    // Parse HTML for meta tags and title
    const titleMatch = bodyText.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : null;

    // Extract meta tags
    const metaTags: Record<string, string> = {};
    const metaRegex = /<meta\s+([^>]*?)\/?\s*>/gi;
    let metaMatch;
    while ((metaMatch = metaRegex.exec(bodyText)) !== null) {
      const attrs = metaMatch[1];
      const nameMatch = attrs.match(/(?:name|property)\s*=\s*["']([^"']+)["']/i);
      const contentMatch = attrs.match(/content\s*=\s*["']([^"']+)["']/i);
      if (nameMatch && contentMatch) {
        metaTags[nameMatch[1]] = contentMatch[1];
      }
    }

    // Extract links count
    const linkMatches = bodyText.match(/<a\s+[^>]*href\s*=/gi);
    const linksCount = linkMatches ? linkMatches.length : 0;

    // Extract script and form counts
    const scriptMatches = bodyText.match(/<script[\s>]/gi);
    const formMatches = bodyText.match(/<form[\s>]/gi);
    const iframeMatches = bodyText.match(/<iframe[\s>]/gi);
    const inputPasswordMatches = bodyText.match(/<input[^>]*type\s*=\s*["']password["'][^>]*>/gi);

    // Parse URL details
    const parsedUrl = new URL(finalUrl);

    // Compute body SHA-256
    const encoder = new TextEncoder();
    const data = encoder.encode(bodyText);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const bodySha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

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
        servingIp: null, // Can't get from edge function
      },
      headers,
      htmlInfo: {
        title,
        metaTags,
        linksCount,
        scriptsCount: scriptMatches ? scriptMatches.length : 0,
        formsCount: formMatches ? formMatches.length : 0,
        iframesCount: iframeMatches ? iframeMatches.length : 0,
        hasPasswordFields: inputPasswordMatches ? inputPasswordMatches.length > 0 : false,
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
