import { describe, expect, it } from 'vitest';

import { parseInjectForm, parseInjectValues } from '../../src/inject-contract.js';

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
