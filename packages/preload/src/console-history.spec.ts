/**********************************************************************
 * Copyright (C) 2026 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 ***********************************************************************/

import { beforeEach, expect, test } from 'vitest';

import {
  ConsoleHistory,
  MAX_CONSOLE_HISTORY_BYTES,
  MAX_CONSOLE_HISTORY_ENTRIES,
  MAX_CONSOLE_MESSAGE_BYTES,
} from './console-history.js';

let history: ConsoleHistory;
const encoder = new TextEncoder();

beforeEach(() => {
  history = new ConsoleHistory();
});

test('preserves message, log type, timestamp, and insertion order', () => {
  const before = Date.now();
  history.append('warn', 'first message');
  history.append('error', 'second message');
  const logs = history.getLogs();
  expect(logs).toEqual([
    { logType: 'warn', date: expect.any(Date), message: 'first message' },
    { logType: 'error', date: expect.any(Date), message: 'second message' },
  ]);
  expect(logs[0]?.date.getTime()).toBeGreaterThanOrEqual(before);
  expect(logs[1]?.date.getTime()).toBeLessThanOrEqual(Date.now());
});

test('evicts oldest messages beyond the entry limit', () => {
  for (let index = 0; index < MAX_CONSOLE_HISTORY_ENTRIES; index++) {
    history.append('log', `message ${index}`);
  }
  expect(history.getLogs()).toHaveLength(MAX_CONSOLE_HISTORY_ENTRIES);
  history.append('log', 'newest message');
  const logs = history.getLogs();
  expect(logs).toHaveLength(MAX_CONSOLE_HISTORY_ENTRIES);
  expect(logs[0]?.message).toBe('message 1');
  expect(logs.at(-1)?.message).toBe('newest message');
});

test('evicts oldest messages beyond the UTF-8 byte limit', () => {
  const message = 'x'.repeat(MAX_CONSOLE_MESSAGE_BYTES);
  const entriesAtLimit = MAX_CONSOLE_HISTORY_BYTES / MAX_CONSOLE_MESSAGE_BYTES;
  for (let index = 0; index < entriesAtLimit; index++) {
    history.append('log', message);
  }
  expect(history.getLogs()).toHaveLength(entriesAtLimit);
  history.append('error', 'newest message');
  const logs = history.getLogs();
  expect(logs).toHaveLength(entriesAtLimit);
  expect(logs.at(-1)?.message).toBe('newest message');
  expect(logs.reduce((bytes, log) => bytes + encoder.encode(log.message).byteLength, 0)).toBeLessThanOrEqual(
    MAX_CONSOLE_HISTORY_BYTES,
  );
});

test.each(['x', '\u00e9', '\u20ac', '\u{1f680}'])('truncates oversized messages without splitting %s', character => {
  history.append('log', character.repeat(MAX_CONSOLE_MESSAGE_BYTES * 2));
  const message = history.getLogs()[0]?.message ?? '';
  expect(message).toMatch(/ \[truncated\]$/);
  expect(message).not.toContain('\uFFFD');
  expect(encoder.encode(message).byteLength).toBeLessThanOrEqual(MAX_CONSOLE_MESSAGE_BYTES);
});

test('preserves a message exactly at the per-message byte limit', () => {
  const message = '\u{1f680}'.repeat(MAX_CONSOLE_MESSAGE_BYTES / 4);
  history.append('log', message);
  expect(history.getLogs()[0]?.message).toBe(message);
});

test('preserves a leading byte order mark in retained messages', () => {
  const message = '\uFEFFdiagnostic';
  history.append('log', message);
  expect(history.getLogs()[0]?.message).toBe(message);
});

test('enforces both limits during sustained mixed-size logging', () => {
  for (let index = 0; index < MAX_CONSOLE_HISTORY_ENTRIES * 3; index++) {
    history.append('log', index % 3 === 0 ? '\u{1f680}'.repeat(MAX_CONSOLE_MESSAGE_BYTES) : `message ${index}`);
    const logs = history.getLogs();
    expect(logs.length).toBeLessThanOrEqual(MAX_CONSOLE_HISTORY_ENTRIES);
    expect(logs.reduce((bytes, log) => bytes + encoder.encode(log.message).byteLength, 0)).toBeLessThanOrEqual(
      MAX_CONSOLE_HISTORY_BYTES,
    );
  }
});

test.each([
  ['password=supersecret', 'password=[REDACTED]'],
  ['{"password":"secret with spaces","status":"ok"}', '{"password":[REDACTED],"status":"ok"}'],
  ['{"password":"secret\\"still secret"}', '{"password":[REDACTED]}'],
  [`client_secret: 'secret with spaces'`, 'client_secret: [REDACTED]'],
  ['token=secret&status=ok', 'token=[REDACTED]&status=ok'],
  ['ACCESS_TOKEN: secret', 'ACCESS_TOKEN: [REDACTED]'],
  ['refresh-token=secret', 'refresh-token=[REDACTED]'],
  ['api_key=secret', 'api_key=[REDACTED]'],
  ['Authorization: Bearer secret', 'Authorization: [REDACTED]'],
  ['{"Authorization":"Basic c2VjcmV0"}', '{"Authorization":[REDACTED]}'],
  ['Bearer secret', 'Bearer [REDACTED]'],
  ['Basic c2VjcmV0', 'Basic [REDACTED]'],
  ['https://user:password@example.com/path', 'https://[REDACTED]@example.com/path'],
  ['--password "secret with spaces" --name example', '--password [REDACTED] --name example'],
  ['--token secret --name example', '--token [REDACTED] --name example'],
  ['-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----', '[REDACTED]'],
  ['-----BEGIN RSA PRIVATE KEY-----\nsecret\n-----END RSA PRIVATE KEY-----', '[REDACTED]'],
  ['-----BEGIN PRIVATE KEY-----\nsecret', '[REDACTED]'],
])('redacts before storage: %s', (input, expected) => {
  history.append('log', input);
  expect(history.getLogs()[0]?.message).toBe(expected);
});

test('redacts a credential crossing the truncation boundary before truncating', () => {
  history.append('log', `password="${'s'.repeat(MAX_CONSOLE_MESSAGE_BYTES * 2)}" useful diagnostic`);
  expect(history.getLogs()[0]?.message).toBe('password=[REDACTED] useful diagnostic');
});

test('does not alter already-redacted credential values', () => {
  const message = '{"token":"[REDACTED]"} Authorization: [REDACTED] --password [REDACTED]';
  history.append('log', message);
  const redacted = history.getLogs()[0]?.message ?? '';
  history.append('log', redacted);
  expect(history.getLogs()[1]?.message).toBe(redacted);
});

test('returned snapshots cannot modify retained entries', () => {
  history.append('log', 'original');
  const logs = history.getLogs();
  const entry = logs[0];
  expect(entry).toBeDefined();
  if (entry) {
    entry.message = 'changed';
    entry.date.setTime(0);
  }
  logs.length = 0;
  expect(history.getLogs()[0]?.message).toBe('original');
  expect(history.getLogs()[0]?.date.getTime()).not.toBe(0);
});

test('clearing resets entries and byte accounting and allows new logging', () => {
  for (let index = 0; index < MAX_CONSOLE_HISTORY_BYTES / MAX_CONSOLE_MESSAGE_BYTES; index++) {
    history.append('log', 'x'.repeat(MAX_CONSOLE_MESSAGE_BYTES));
  }
  history.clear();
  expect(history.getLogs()).toEqual([]);
  history.clear();
  history.append('warn', 'after clear');
  expect(history.getLogs()).toEqual([{ logType: 'warn', date: expect.any(Date), message: 'after clear' }]);
});
