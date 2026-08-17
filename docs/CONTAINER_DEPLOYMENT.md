# API-only container deployment

The optional container is for API-target workflows where browser screenshots, persistent browser profiles, and interactive login are not required.

```text
docker compose up --build
```

The supplied Compose file publishes `127.0.0.1:8091` only, drops Linux capabilities, enables `no-new-privileges`, uses a read-only root filesystem, and stores AdverScope state in a named volume. Open `http://127.0.0.1:8091/` locally.

Configure a host model with `ADVERSCOPE_CONTAINER_MODEL_BASE_URL`, normally using `host.docker.internal`. For OpenAI or Z.AI, set `ADVERSCOPE_CONTAINER_PROVIDER`, `ADVERSCOPE_CONTAINER_MODEL`, and the API-key environment-variable name, then inject the corresponding key into the container through an approved local secret mechanism. Do not put a key in Compose source, `.env` committed to Git, or the AdverScope configuration file.

The container's internal `0.0.0.0` listener is approved only behind the supplied host-loopback mapping. Do not change the mapping to `0.0.0.0:8091`. Remote container exposure requires an organization-approved TLS/authentication reverse proxy and is outside the Beta support boundary.

Back up the named volume with `adverscope backup create` from an equivalent mounted environment before upgrades. Browser-session transfer is unavailable because the image intentionally omits Node.js, Playwright, and a browser.
