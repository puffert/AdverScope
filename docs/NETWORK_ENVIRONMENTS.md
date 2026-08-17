# Corporate network, proxy, CA, VPN, and firewall setup

AdverScope does not disable certificate verification. Resolve enterprise network requirements explicitly and record them as assessment preconditions.

## Proxies

Python model and API traffic follows standard `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables where the underlying HTTP client supports them. Include loopback, local model endpoints, VPN-only targets, and approved internal domains in `NO_PROXY` when they must bypass the corporate proxy. Node-based browser navigation follows the installed browser and operating-system proxy policy; it is not automatically configured from the Python process.

Never put proxy credentials in project documents, target headers, saved configuration, issue reports, or command history. Use the operating-system credential facility or approved environment injection.

## Custom certificate authorities

Install the customer-approved root CA in the operating-system trust store for Chrome/Edge. Configure Python with the approved CA bundle through `SSL_CERT_FILE` when the operating-system store is not used by the runtime. Configure Node with `NODE_EXTRA_CA_CERTS` when package or helper traffic requires the same CA. Do not use insecure TLS flags or `ignoreHTTPSErrors` as a workaround.

## VPN and routing

Connect the authorized tester VPN before running `adverscope doctor` or target preflight. Verify DNS, route ownership, split tunnelling, and the exact target origin outside AdverScope. A VPN route does not expand project scope. AdverScope blocks top-level browser navigation outside the configured origin and does not follow API redirects outside the authorized route contract.

## Firewalls

Allow only the required paths:

- local UI: loopback TCP on the configured AdverScope port;
- local model: configured OpenAI-compatible model port or SSH tunnel;
- remote provider: outbound HTTPS to the selected provider endpoint;
- target: approved target origins and ports;
- optional callbacks: only explicitly mapped collaborator endpoints.

For direct remote API mode, restrict inbound traffic to the tester network, use TLS, use an unpredictable environment-provided bearer token, rotate it after the engagement, and retain access logs outside AdverScope when required. Prefer a hardened reverse proxy bound to AdverScope's loopback address when an organization already has approved identity and TLS infrastructure.

Run `adverscope doctor` after proxy, CA, VPN, firewall, or provider changes. A connectivity pass is not a security verdict.
