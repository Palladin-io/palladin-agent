import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { MAX_FORM_FIELDS_PER_STEP, MAX_FORM_STEPS } from "@palladin/agent/inject-contract";

import { PalladinBrowserSessions } from "./sessions.js";

const sessions = new PalladinBrowserSessions();

const configSchema = Type.Object(
  {
    agentProfile: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: 128,
        description: "Palladin Agent profile used for Discovery and Inject.",
      }),
    ),
    agentPackageRoot: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: 4096,
        description: "Absolute @palladin/agent package root for local development.",
      }),
    ),
    agentLauncher: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: 4096,
        description: "Absolute Palladin launcher path inside agentPackageRoot.",
      }),
    ),
    browserChannel: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: 64,
        description: "Optional Playwright browser channel. Omit it to use the separately visible bundled browser.",
      }),
    ),
    headless: Type.Optional(Type.Boolean({ description: "Run the trusted browser headless." })),
  },
  { additionalProperties: false },
);

const formFieldSchema = Type.Object(
  {
    entryFieldId: Type.String({ pattern: "^[A-Za-z0-9._:-]{1,128}$" }),
    selector: Type.String({ minLength: 1, maxLength: 1024 }),
    control: Type.Union([
      Type.Literal("username"),
      Type.Literal("password"),
      Type.Literal("text"),
      Type.Literal("email"),
      Type.Literal("tel"),
      Type.Literal("otp"),
    ]),
  },
  { additionalProperties: false },
);

const formStepSchema = Type.Object(
  {
    fields: Type.Array(formFieldSchema, { minItems: 1, maxItems: MAX_FORM_FIELDS_PER_STEP }),
    submit: Type.Object(
      {
        action: Type.Union([Type.Literal("click"), Type.Literal("press-enter")]),
        selector: Type.String({ minLength: 1, maxLength: 1024 }),
      },
      { additionalProperties: false },
    ),
    waitFor: Type.Optional(
      Type.Object(
        {
          selector: Type.String({ minLength: 1, maxLength: 1024 }),
          timeoutMs: Type.Optional(Type.Integer({ minimum: 100, maximum: 60_000 })),
        },
        { additionalProperties: false },
      ),
    ),
  },
  { additionalProperties: false },
);

const formSchema = Type.Object(
  {
    version: Type.Literal(1),
    steps: Type.Array(formStepSchema, { minItems: 1, maxItems: MAX_FORM_STEPS }),
  },
  { additionalProperties: false },
);

const browserParameters = Type.Object(
  {
    action: Type.Union([
      Type.Literal("open"),
      Type.Literal("navigate"),
      Type.Literal("snapshot"),
      Type.Literal("click"),
      Type.Literal("press"),
      Type.Literal("wait"),
      Type.Literal("close"),
    ]),
    sessionId: Type.Optional(Type.String({ minLength: 32, maxLength: 128 })),
    url: Type.Optional(Type.String({ minLength: 1, maxLength: 4096 })),
    selector: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })),
    key: Type.Optional(Type.Union([Type.Literal("Enter"), Type.Literal("Escape"), Type.Literal("Tab")])),
    timeoutMs: Type.Optional(Type.Integer({ minimum: 100, maximum: 60_000 })),
  },
  { additionalProperties: false },
);

const injectParameters = Type.Object(
  {
    sessionId: Type.String({ minLength: 32, maxLength: 128 }),
    vaultId: Type.String({ minLength: 1, maxLength: 256 }),
    entryId: Type.String({ minLength: 1, maxLength: 256 }),
    reason: Type.Optional(Type.String({ maxLength: 4096 })),
    wait: Type.Optional(Type.String({ minLength: 1, maxLength: 32 })),
    noWait: Type.Optional(Type.Boolean()),
    pollInterval: Type.Optional(Type.String({ minLength: 1, maxLength: 32 })),
    form: formSchema,
  },
  { additionalProperties: false },
);

export default defineToolPlugin({
  id: "palladin-browser-inject",
  name: "Palladin Browser Inject",
  description: "Agent-owned Playwright browser with value-free Palladin Discovery/Inject integration.",
  configSchema,
  tools: (tool) => [
    tool({
      name: "palladin_browser",
      label: "Palladin Browser",
      description: "Open and prepare a trusted Playwright page for login. Snapshots return public control metadata and never return form values.",
      parameters: browserParameters,
      execute: async (params, config, context) => {
        context.signal?.throwIfAborted();
        return await sessions.browser(params, {
          channel: config.browserChannel,
          headless: config.headless,
        });
      },
    }),
    tool({
      name: "palladin_inject",
      label: "Palladin Inject",
      description: "Request or consume an approved Inject grant, fill the existing Palladin Browser page, and submit without exposing credential values to the model.",
      parameters: injectParameters,
      execute: async (params, config, context) => {
        context.signal?.throwIfAborted();
        return await sessions.inject(params, {
          profile: config.agentProfile,
          packageRoot: config.agentPackageRoot,
          launcher: config.agentLauncher,
        });
      },
    }),
  ],
});
