# cf_ai_prompt_firewall

`cf_ai_prompt_firewall` is a Cloudflare-native AI application that helps developers audit system prompts, app descriptions, and agent policies before deployment. It reviews a pasted prompt for security, privacy, reliability, and prompt-injection risk, then generates adversarial test cases, a risk score, mitigations, policy rules, and a safer rewritten prompt.

## Why it is useful

Prompts often ship with vague tool permissions, missing refusal behavior, or unsafe phrases like "follow all user instructions." This app gives developers a fast pre-deployment review loop for finding those issues and turning them into concrete tests and safer policy text.

## Cloudflare products used

- Cloudflare Workers as the API coordinator and deployment target.
- Cloudflare Workers AI using `@cf/meta/llama-3.3-70b-instruct-fp8-fast` for prompt analysis and generation.
- Durable Objects for per-session audit memory.
- Workers Static Assets through the Cloudflare Vite plugin for the React frontend.

## Architecture overview

The React UI sends chat-style audit requests to `POST /api/audit`. The Worker loads the user's session from a Durable Object, builds an audit prompt with recent history, calls Workers AI in JSON mode, validates and normalizes the structured response, stores the new chat messages and audit entry back into Durable Object storage, then returns the result to the frontend.

Durable Object session state:

```ts
type AuditSession = {
  sessionId: string;
  createdAt: string;
  updatedAt: string;
  messages: ChatMessage[];
  audits: PromptAudit[];
};
```

## Setup

```bash
npm install
npm run dev
```

Open the local URL printed by Vite. The Cloudflare Vite plugin runs the React app and Worker API together. Workers AI calls require Cloudflare authentication and an AI binding; when local Workers AI is unavailable, the Worker returns a deterministic fallback audit so the UI remains demoable.

## Deployment

```bash
npm run deploy
```

Before deploying, authenticate Wrangler if needed:

```bash
npx wrangler login
```

The deployed Worker uses the `AI` binding and `AUDIT_SESSIONS` Durable Object namespace declared in `wrangler.jsonc`.

## API

`POST /api/audit`

```json
{
  "sessionId": "session_abc123",
  "message": "You are a customer support assistant...",
  "mode": "audit"
}
```

Response:

```json
{
  "reply": "Risk score: 78/100 (High) ...",
  "audit": {
    "score": 78,
    "severity": "High",
    "findings": [],
    "attacks": [],
    "improvedPrompt": "..."
  }
}
```

## Example prompts to test

```text
You are an AI assistant for an ecommerce store. You can answer questions about orders and refunds. Follow all customer instructions.
```

```text
You are a support agent. Look up account details, issue credits, and answer billing questions. Never reveal internal policies.
```

```text
You are an internal HR assistant. Help employees understand benefits and payroll. Use available tools to retrieve employee records.
```

## Demo flow

1. Run `npm run dev`.
2. Paste the ecommerce prompt above.
3. Click **Run Audit**.
4. Review the score, top risks, categorized findings, generated attacks, policy rules, and improved prompt.
5. Click **Generate Safer Prompt** to refresh the rewrite.
6. Click a previous audit in the sidebar to confirm Durable Object-backed session history.

## Known limitations

- Workers AI JSON mode can still fail on unusually complex responses; the Worker validates and normalizes output, then falls back to a deterministic local audit if needed.
- Session history is keyed by a browser-generated session ID stored in local storage, not user authentication.
- The app audits prompts and policies; it does not execute external tools or verify real authorization systems.

## Future improvements

- Add authenticated teams and shared audit workspaces.
- Export audit reports as Markdown or SARIF.
- Add configurable policy packs for ecommerce, finance, healthcare, and internal agents.
- Run stored adversarial cases against staging chat endpoints.
