import { describe, expect, it } from 'vitest';
import { AjvJsonSchemaValidator } from '@modelcontextprotocol/sdk/validation/ajv';
import type { JsonSchemaType } from '@modelcontextprotocol/sdk/validation';

import {
  injectFormJsonSchema,
  parseInjectForm,
  parseInjectValues,
} from '../../src/inject-contract.js';

const form = {
  version: 1,
  steps: [
    {
      fields: [{ entryFieldId: 'credential.username', selector: '#user', control: 'username' }],
      submit: { action: 'press-enter', selector: '#user' },
      waitFor: { selector: '#password' },
    },
    {
      fields: [{ entryFieldId: 'credential.password', selector: '#password', control: 'password' }],
      submit: { action: 'click', selector: 'button[type="submit"]' },
    },
  ],
};

describe('Inject form contract', () => {
  it('accepts a bounded multi-step value-free definition', () => {
    expect(parseInjectForm(form)).toEqual(form);
  });

  it('rejects duplicate fields, missing transitions and executable additions', () => {
    expect(parseInjectForm({
      version: 1,
      steps: [{ ...form.steps[0], waitFor: undefined }, form.steps[1]],
    })).toBeNull();
    expect(parseInjectForm({ ...form, javascript: 'alert(1)' })).toBeNull();
    expect(parseInjectForm({
      version: 1,
      steps: [{
        fields: [
          { entryFieldId: 'credential.password', selector: '#one', control: 'password' },
          { entryFieldId: 'credential.password', selector: '#two', control: 'password' },
        ],
        submit: { action: 'click', selector: '#submit' },
      }],
    })).toBeNull();
  });

  it('publishes the same aggregate field bound enforced by the parser', () => {
    const validateSchema = new AjvJsonSchemaValidator().getValidator(
      injectFormJsonSchema as unknown as JsonSchemaType,
    );
    const fields = (step: number, count: number) => Array.from({ length: count }, (_, index) => ({
      entryFieldId: `credential.step${step}.${index}`,
      selector: `#step-${step}-${index}`,
      control: 'text',
    }));
    const bounded = {
      version: 1,
      steps: [
        {
          fields: fields(1, 8),
          submit: { action: 'click', selector: '#next' },
          waitFor: { selector: '#step-2' },
        },
        { fields: fields(2, 8), submit: { action: 'click', selector: '#submit' } },
      ],
    };
    const oversized = {
      ...bounded,
      steps: [
        { ...bounded.steps[0], fields: fields(1, 9) },
        { ...bounded.steps[1], fields: fields(2, 9) },
      ],
    };

    expect(validateSchema(bounded).valid).toBe(true);
    expect(parseInjectForm(bounded)).not.toBeNull();
    expect(validateSchema(oversized).valid).toBe(false);
    expect(parseInjectForm(oversized)).toBeNull();
  });

  it('requires exactly one private value for each declared field', () => {
    const parsed = parseInjectForm(form);
    expect(parsed).not.toBeNull();
    expect(parseInjectValues([
      { entryFieldId: 'credential.username', value: 'fixture-user' },
      { entryFieldId: 'credential.password', value: 'fixture-password' },
    ], parsed!)).not.toBeNull();
    expect(parseInjectValues([
      { entryFieldId: 'credential.password', value: 'fixture-password' },
    ], parsed!)).toBeNull();
    expect(parseInjectValues([
      { entryFieldId: 'credential.username', value: 'fixture-user' },
      { entryFieldId: 'credential.password', value: 'fixture-password' },
      { entryFieldId: 'credential.totp', value: '123456' },
    ], parsed!)).toBeNull();
  });
});
