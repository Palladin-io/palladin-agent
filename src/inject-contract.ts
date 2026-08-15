/** Provider-neutral, value-free Inject form contract. */
export const INJECT_FORM_VERSION = 1 as const;
export const MAX_FORM_STEPS = 8;
export const MAX_FORM_FIELDS = 16;

export type InjectControl = 'username' | 'password' | 'text' | 'email' | 'tel' | 'otp';

export interface InjectFormField {
  entryFieldId: string;
  selector: string;
  control: InjectControl;
}

export interface InjectSubmitAction {
  action: 'click' | 'press-enter';
  selector: string;
}

export interface InjectWaitCondition {
  selector: string;
  timeoutMs?: number;
}

export interface InjectFormStep {
  fields: InjectFormField[];
  submit: InjectSubmitAction;
  waitFor?: InjectWaitCondition;
}

export interface InjectFormDefinition {
  version: typeof INJECT_FORM_VERSION;
  steps: InjectFormStep[];
}

export interface InjectFieldValue {
  entryFieldId: string;
  value: string;
}

// JSON Schema cannot sum nested array lengths. Tightening each step by the
// declared step count gives the same deterministic <= MAX_FORM_FIELDS bound
// that the TypeScript and Rust validators enforce.
const aggregateFieldLimitSchema = Array.from({ length: MAX_FORM_STEPS }, (_, index) => {
  const minimumStepCount = index + 1;
  return {
    if: {
      properties: { steps: { minItems: minimumStepCount } },
      required: ['steps'],
    },
    then: {
      properties: {
        steps: {
          items: {
            properties: {
              fields: { maxItems: Math.floor(MAX_FORM_FIELDS / minimumStepCount) },
            },
          },
        },
      },
    },
  };
});

export const injectFormJsonSchema = {
  type: 'object',
  additionalProperties: false,
  allOf: aggregateFieldLimitSchema,
  properties: {
    version: { const: 1 },
    steps: {
      type: 'array', minItems: 1, maxItems: MAX_FORM_STEPS,
      items: {
        type: 'object', additionalProperties: false,
        properties: {
          fields: {
            type: 'array', minItems: 1, maxItems: MAX_FORM_FIELDS,
            items: {
              type: 'object', additionalProperties: false,
              properties: {
                entryFieldId: { type: 'string', pattern: '^[A-Za-z0-9._:-]{1,128}$' },
                selector: { type: 'string', minLength: 1, maxLength: 1024 },
                control: { enum: ['username', 'password', 'text', 'email', 'tel', 'otp'] },
              },
              required: ['entryFieldId', 'selector', 'control'],
            },
          },
          submit: {
            type: 'object', additionalProperties: false,
            properties: {
              action: { enum: ['click', 'press-enter'] },
              selector: { type: 'string', minLength: 1, maxLength: 1024 },
            },
            required: ['action', 'selector'],
          },
          waitFor: {
            type: 'object', additionalProperties: false,
            properties: {
              selector: { type: 'string', minLength: 1, maxLength: 1024 },
              timeoutMs: { type: 'integer', minimum: 100, maximum: 60_000 },
            },
            required: ['selector'],
          },
        },
        required: ['fields', 'submit'],
      },
    },
  },
  required: ['version', 'steps'],
} as const;

const CONTROLS = new Set<InjectControl>(['username', 'password', 'text', 'email', 'tel', 'otp']);
const FIELD_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function parseInjectForm(value: unknown): InjectFormDefinition | null {
  if (!isRecord(value) || !onlyKeys(value, ['version', 'steps'])
    || value.version !== INJECT_FORM_VERSION || !Array.isArray(value.steps)
    || value.steps.length < 1 || value.steps.length > MAX_FORM_STEPS) return null;
  let fieldCount = 0;
  const maxFieldsPerStep = Math.floor(MAX_FORM_FIELDS / value.steps.length);
  const steps: InjectFormStep[] = [];
  for (let index = 0; index < value.steps.length; index += 1) {
    const rawStep = value.steps[index];
    if (!isRecord(rawStep) || !onlyKeys(rawStep, ['fields', 'submit', 'waitFor'])
      || !Array.isArray(rawStep.fields) || rawStep.fields.length < 1
      || rawStep.fields.length > maxFieldsPerStep) return null;
    const fields: InjectFormField[] = [];
    const stepFieldIds = new Set<string>();
    for (const rawField of rawStep.fields) {
      if (!isRecord(rawField) || !onlyKeys(rawField, ['entryFieldId', 'selector', 'control'])
        || typeof rawField.entryFieldId !== 'string' || !FIELD_ID.test(rawField.entryFieldId)
        || !selector(rawField.selector) || typeof rawField.control !== 'string'
        || !CONTROLS.has(rawField.control as InjectControl)
        || stepFieldIds.has(rawField.entryFieldId)) return null;
      stepFieldIds.add(rawField.entryFieldId);
      fieldCount += 1;
      if (fieldCount > MAX_FORM_FIELDS) return null;
      fields.push(rawField as unknown as InjectFormField);
    }
    const rawSubmit = rawStep.submit;
    if (!isRecord(rawSubmit) || !onlyKeys(rawSubmit, ['action', 'selector'])
      || (rawSubmit.action !== 'click' && rawSubmit.action !== 'press-enter')
      || !selector(rawSubmit.selector)
      || (rawSubmit.action === 'press-enter'
        && !fields.some((field) => field.selector === rawSubmit.selector))) return null;
    let waitFor: InjectWaitCondition | undefined;
    if (rawStep.waitFor !== undefined) {
      if (!isRecord(rawStep.waitFor) || !onlyKeys(rawStep.waitFor, ['selector', 'timeoutMs'])
        || !selector(rawStep.waitFor.selector)
        || (rawStep.waitFor.timeoutMs !== undefined
          && (typeof rawStep.waitFor.timeoutMs !== 'number'
            || !Number.isSafeInteger(rawStep.waitFor.timeoutMs)
            || rawStep.waitFor.timeoutMs < 100
            || rawStep.waitFor.timeoutMs > 60_000))) return null;
      waitFor = rawStep.waitFor as unknown as InjectWaitCondition;
    }
    if (index < value.steps.length - 1 && waitFor === undefined) return null;
    steps.push({ fields, submit: rawSubmit as unknown as InjectSubmitAction, ...(waitFor ? { waitFor } : {}) });
  }
  return { version: INJECT_FORM_VERSION, steps };
}

export function parseInjectValues(
  value: unknown,
  form: InjectFormDefinition,
): InjectFieldValue[] | null {
  if (!Array.isArray(value)) return null;
  const required = new Set(form.steps.flatMap((step) => step.fields.map((field) => field.entryFieldId)));
  const seen = new Set<string>();
  const values: InjectFieldValue[] = [];
  for (const item of value) {
    if (!isRecord(item) || !onlyKeys(item, ['entryFieldId', 'value'])
      || typeof item.entryFieldId !== 'string' || !required.has(item.entryFieldId)
      || seen.has(item.entryFieldId) || typeof item.value !== 'string'
      || item.value.length > 64 * 1024) return null;
    seen.add(item.entryFieldId);
    values.push(item as unknown as InjectFieldValue);
  }
  return seen.size === required.size ? values : null;
}

function selector(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 1024
    && value === value.trim() && !value.includes('\0');
}

function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
