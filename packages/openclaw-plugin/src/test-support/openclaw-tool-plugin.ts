interface ToolDefinition {
  name: string;
  parameters: unknown;
}

interface ToolPluginDefinition {
  tools: (tool: <T extends ToolDefinition>(definition: T) => T) => ToolDefinition[];
}

interface ToolPluginMetadata {
  tools: ToolDefinition[];
}

const metadata = new WeakMap<object, ToolPluginMetadata>();

export function defineToolPlugin(definition: ToolPluginDefinition): object {
  const entry = {};
  metadata.set(entry, { tools: definition.tools((tool) => tool) });
  return entry;
}

export function getToolPluginMetadata(entry: unknown): ToolPluginMetadata | undefined {
  return typeof entry === "object" && entry !== null ? metadata.get(entry) : undefined;
}
