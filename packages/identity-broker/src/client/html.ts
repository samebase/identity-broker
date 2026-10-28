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
  a.button, button { display: block; width: 100%; box-sizing: border-box; padding: 0.75rem 1rem;
    font: inherit; color: #111; background: #fff; border: 1px solid #111; text-align: center;
    text-decoration: none; cursor: pointer; }
  input { display: block; width: 100%; box-sizing: border-box; padding: 0.75rem 1rem; font: inherit;
    border: 1px solid #111; margin: 1rem 0; }
  .error { color: #b00020; }
  .muted { color: #555; }
`;

export function page(title: string, body: string): Response {
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
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
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
  connectors: Array<{ name: string; label: string; href: string }>;
  denyHref: string;
}): Response {
  const buttons = args.connectors
    .map(
      (connector) =>
        `<a class="button" href="${escape(connector.href)}">Continue with ${escape(connector.label)}</a>`,
    )
    .join("\n");
  const consent = args.firstParty
    ? ""
    : `<p class="muted">${escape(args.appName)} will receive your identity from the provider you choose: a stable id, your name, and your verified email address.</p>`;
  const deny = args.firstParty
    ? ""
    : `<p><a href="${escape(args.denyHref)}">Cancel and return to ${escape(args.appName)}</a></p>`;
  return page(
    `Sign in to ${args.appName}`,
    `<h1>Sign in to ${escape(args.appName)}</h1>${consent}<div class="list">${buttons}</div>${deny}`,
  );
}

export function emailAddressPage(args: {
  appName: string;
  action: string;
  requestId: string;
  error?: string;
}): Response {
  const error = args.error === undefined ? "" : `<p class="error">${escape(args.error)}</p>`;
  return page(
    `Sign in to ${args.appName}`,
    `<h1>Sign in to ${escape(args.appName)}</h1><p>Enter your email address. A six-digit code is sent to it.</p>${error}
<form method="post" action="${escape(args.action)}">
<input type="hidden" name="request" value="${escape(args.requestId)}">
<input type="hidden" name="step" value="send">
<input type="email" name="email" required autocomplete="email" autofocus placeholder="you@example.com">
<button type="submit">Send code</button>
</form>`,
  );
}

export function emailCodePage(args: {
  appName: string;
  action: string;
  requestId: string;
  email: string;
  error?: string;
}): Response {
  const error = args.error === undefined ? "" : `<p class="error">${escape(args.error)}</p>`;
  return page(
    `Sign in to ${args.appName}`,
    `<h1>Check your email</h1><p>Enter the six-digit code sent to ${escape(args.email)}.</p>${error}
<form method="post" action="${escape(args.action)}">
<input type="hidden" name="request" value="${escape(args.requestId)}">
<input type="hidden" name="step" value="verify">
<input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" required autocomplete="one-time-code" autofocus placeholder="000000">
<button type="submit">Continue</button>
</form>`,
  );
}

export function errorPage(title: string, message: string, status = 400): Response {
  const response = page(title, `<h1>${escape(title)}</h1><p>${escape(message)}</p>`);
  return new Response(response.body, { status, headers: response.headers });
}
