/** The few pages the broker renders itself. Plain HTML, one stylesheet, no script. */

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
  .list { display: grid; gap: 0.5rem; margin: 1.5rem 0; }
  a.button { display: block; width: 100%; box-sizing: border-box; padding: 0.75rem 1rem;
    font: inherit; color: #111; background: #fff; border: 1px solid #111; text-align: center;
    text-decoration: none; cursor: pointer; }
  .muted { color: #555; }
`;

export function page(title: string, body: string, status = 200): Response {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${escape(title)}</title>
<style>${STYLE}</style>
</head>
<body><main>${body}</main></body>
</html>`;
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      // No page of the broker may be framed: the chooser doubles as consent.
      "Content-Security-Policy": "frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
    },
  });
}

/**
 * The connector choice. A third-party app gets the consent wording and a deny link; a first-party
 * app only sees the buttons.
 */
export function chooserPage(args: {
  appName: string;
  firstParty: boolean;
  /** The granted scopes: the consent names only what they release. */
  scopes: string[];
  connectors: Array<{ name: string; label: string; href: string }>;
  denyHref: string;
}): Response {
  const buttons = args.connectors
    .map(
      (connector) =>
        `<a class="button" href="${escape(connector.href)}">Continue with ${escape(connector.label)}</a>`,
    )
    .join("\n");
  const released = [
    "a stable id",
    ...(args.scopes.includes("profile") ? ["your name and picture"] : []),
    ...(args.scopes.includes("email") ? ["your verified email address"] : []),
  ];
  const list =
    released.length <= 2
      ? released.join(" and ")
      : `${released.slice(0, -1).join(", ")}, and ${released.slice(-1).join("")}`;
  const consent = args.firstParty
    ? ""
    : `<p class="muted">${escape(args.appName)} will receive your identity from the provider you choose: ${list}.</p>`;
  const deny = args.firstParty
    ? ""
    : `<p><a href="${escape(args.denyHref)}">Cancel and return to ${escape(args.appName)}</a></p>`;
  return page(
    `Sign in to ${args.appName}`,
    `<h1>Sign in to ${escape(args.appName)}</h1>${consent}<div class="list">${buttons}</div>${deny}`,
  );
}

export function errorPage(title: string, message: string, status = 400): Response {
  return page(title, `<h1>${escape(title)}</h1><p>${escape(message)}</p>`, status);
}
