/** The error page the broker renders when a request has no trusted redirect target. */

function escape(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

const STYLE = `
  body { margin: 0; font: 16px/1.5 system-ui, sans-serif; color: #111; background: #fff; }
  main { max-width: 24rem; margin: 10vh auto; padding: 0 1rem; }
  h1 { font-size: 1.25rem; font-weight: 600; }
  p { margin: 0.5rem 0; }
`;

export function errorPage(title: string, message: string, status = 400): Response {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escape(title)}</title>
<style>${STYLE}</style>
</head>
<body><main><h1>${escape(title)}</h1><p>${escape(message)}</p></main></body>
</html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      // The page names the request it refuses; no other site may frame it.
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    },
  });
}
