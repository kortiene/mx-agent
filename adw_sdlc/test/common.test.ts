import { describe, expect, it } from 'vitest';

import { AdwError } from '../src/errors.js';
import { parseJson, shellSplit, stripFrontmatter, substituteArgs } from '../src/common.js';

describe('substituteArgs', () => {
  it('substitutes positionals, $@, $ARGUMENTS, and slices like the Python engine', () => {
    const args = ['12', 'fix', 'the', 'bug'];
    expect(substituteArgs('issue $1: $2', args)).toBe('issue 12: fix');
    expect(substituteArgs('all: $@', args)).toBe('all: 12 fix the bug');
    expect(substituteArgs('all: $ARGUMENTS', args)).toBe('all: 12 fix the bug');
    expect(substituteArgs('rest: ${@:2}', args)).toBe('rest: fix the bug');
    expect(substituteArgs('two: ${@:2:2}', args)).toBe('two: fix the');
  });

  it('renders missing positionals as empty strings', () => {
    expect(substituteArgs('a $1 b $9 c', ['x'])).toBe('a x b  c');
  });
});

describe('stripFrontmatter', () => {
  it('removes a YAML frontmatter block', () => {
    expect(stripFrontmatter('---\ntitle: x\n---\nbody')).toBe('body');
  });

  it('leaves text without frontmatter untouched', () => {
    expect(stripFrontmatter('plain body')).toBe('plain body');
    expect(stripFrontmatter('---\nunterminated')).toBe('---\nunterminated');
  });
});

describe('parseJson', () => {
  it('parses raw JSON', () => {
    expect(parseJson('{"a": 1}')).toEqual({ a: 1 });
  });

  it('prefers the LAST fenced block (agents emit the contract block last)', () => {
    const text = 'intro\n```json\n{"a": 1}\n```\nmore prose\n```json\n{"b": 2}\n```\n';
    expect(parseJson(text)).toEqual({ b: 2 });
  });

  it('accepts a bare ``` fence and JSON embedded in prose', () => {
    expect(parseJson('```\n{"a": 1}\n```')).toEqual({ a: 1 });
    expect(parseJson('the answer is {"a": 1} as shown')).toEqual({ a: 1 });
  });

  it('enforces the expected top-level type', () => {
    expect(() => parseJson('[1, 2]', 'object')).toThrow(AdwError);
    expect(() => parseJson('{"a": 1}', 'array')).toThrow(AdwError);
  });

  it('raises AdwError on empty or unparseable output', () => {
    expect(() => parseJson(null)).toThrow(AdwError);
    expect(() => parseJson('no json here at all')).toThrow(AdwError);
  });
});

describe('shellSplit', () => {
  it('splits on whitespace and honors quotes', () => {
    expect(shellSplit('cargo test --all')).toEqual(['cargo', 'test', '--all']);
    expect(shellSplit("bash -c 'echo a b'")).toEqual(['bash', '-c', 'echo a b']);
    expect(shellSplit('run "two words" x')).toEqual(['run', 'two words', 'x']);
  });
});
