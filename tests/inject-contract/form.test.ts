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

  it('accepts uneven forms within the same per-step schema and parser bound', () => {
    const validateSchema = new AjvJsonSchemaValidator().getValidator(
      injectFormJsonSchema as unknown as JsonSchemaType,
    );
    const fields = (step: number, count: number) => Array.from({ length: count }, (_, index) => ({
      entryFieldId: `credential.step${step}.${index}`,
      selector: `#step-${step}-${index}`,
      control: 'text',
    }));
    const makeForm = (counts: number[]) => ({
      version: 1,
      steps: counts.map((count, index) => ({
        fields: fields(index + 1, count),
        submit: { action: 'click', selector: index + 1 === counts.length ? '#submit' : '#next' },
        ...(index + 1 === counts.length ? {} : { waitFor: { selector: `#step-${index + 2}` } }),
      })),
    });

    for (const counts of [[9, 7], [6, 5, 5]]) {
      const uneven = makeForm(counts);
      expect(validateSchema(uneven).valid).toBe(true);
      expect(parseInjectForm(uneven)).not.toBeNull();
    }

    const oversizedStep = makeForm([17]);
    expect(validateSchema(oversizedStep).valid).toBe(false);
    expect(parseInjectForm(oversizedStep)).toBeNull();
  });

  it('keeps private value delivery globally bounded at 16 fields', () => {
    const fields = (step: number, count: number) => Array.from({ length: count }, (_, index) => ({
      entryFieldId: `credential.step${step}.${index}`,
      selector: `#step-${step}-${index}`,
      control: 'text',
    }));
    const seventeenFieldForm = parseInjectForm({
      version: 1,
      steps: [
        {
          fields: fields(1, 9),
          submit: { action: 'click', selector: '#next' },
          waitFor: { selector: '#step-2' },
        },
        { fields: fields(2, 8), submit: { action: 'click', selector: '#submit' } },
      ],
    });

    expect(seventeenFieldForm).not.toBeNull();
    const values = seventeenFieldForm!.steps.flatMap((step) => step.fields.map((field) => ({
      entryFieldId: field.entryFieldId,
      value: 'fixture-value',
    })));
    expect(parseInjectValues(values, seventeenFieldForm!)).toBeNull();
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
