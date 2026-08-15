declare module "openclaw/plugin-sdk/tool-plugin" {
  export interface ToolDefinition {
    name: string;
    label: string;
    description: string;
    parameters: unknown;
    execute: (
      params: any,
      config: any,
      context: { signal?: AbortSignal },
    ) => Promise<unknown>;
  }

  export interface ToolPluginDefinition {
    id: string;
    name: string;
    description: string;
    configSchema: unknown;
    tools: (tool: (definition: ToolDefinition) => ToolDefinition) => ToolDefinition[];
  }

  export interface ToolPluginMetadata {
    tools: ToolDefinition[];
  }

  export function defineToolPlugin(definition: ToolPluginDefinition): object;
  export function getToolPluginMetadata(entry: unknown): ToolPluginMetadata | undefined;
}
