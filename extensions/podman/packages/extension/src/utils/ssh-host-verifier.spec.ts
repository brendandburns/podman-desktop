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

import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { window } from '@podman-desktop/api';
import { afterEach, beforeEach, expect, test, vi } from 'vitest';

import { createSshHostVerifier } from './ssh-host-verifier';

let storagePath: string;
const key = Buffer.from('server public key');
const otherKey = Buffer.from('different server public key');
const onError = vi.fn();

beforeEach(async () => {
  vi.resetAllMocks();
  storagePath = await mkdtemp(join(tmpdir(), 'podman-host-verifier-'));
  vi.mocked(window.showWarningMessage).mockResolvedValue('Trust host key');
  vi.mocked(window.showErrorMessage).mockResolvedValue(undefined);
});

afterEach(async () => {
  await rm(storagePath, { recursive: true, force: true });
});

async function verify(publicKey = key, host = 'remote.example', port = 22): Promise<boolean> {
  const verifier = createSshHostVerifier(storagePath, host, port, onError);
  return new Promise(resolve => verifier(publicKey, resolve));
}

async function fingerprintFile(): Promise<string> {
  const directory = join(storagePath, 'ssh-known-hosts');
  const files = await readdir(directory);
  expect(files).toHaveLength(1);
  return join(directory, files[0]!);
}

test('requires explicit first-use approval and persists the SHA256 fingerprint', async () => {
  expect(await verify()).toBe(true);
  const fingerprint = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
  expect(window.showWarningMessage).toHaveBeenCalledWith(
    expect.stringContaining(`[remote.example]:22 is unknown. SHA256 fingerprint: ${fingerprint}`),
    'Trust host key',
    'Cancel',
  );
  const file = await fingerprintFile();
  expect(await readFile(file, 'utf8')).toBe(`${fingerprint}\n`);
  if (process.platform !== 'win32') {
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await stat(join(storagePath, 'ssh-known-hosts'))).mode & 0o777).toBe(0o700);
  }
  expect(onError).not.toHaveBeenCalled();
});

test.each(['Cancel', undefined])('rejects unknown keys when approval is %s', async approval => {
  vi.mocked(window.showWarningMessage).mockResolvedValue(approval);
  expect(await verify()).toBe(false);
  expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('not trusted') }));
  expect(window.showErrorMessage).toHaveBeenCalled();
  expect(await readdir(storagePath)).toEqual([]);
});

test('accepts a previously approved key without another prompt', async () => {
  expect(await verify()).toBe(true);
  vi.mocked(window.showWarningMessage).mockClear();
  expect(await verify()).toBe(true);
  expect(window.showWarningMessage).not.toHaveBeenCalled();
});

test('rejects a changed key without prompting or overwriting the pin', async () => {
  expect(await verify()).toBe(true);
  const file = await fingerprintFile();
  const pinned = await readFile(file, 'utf8');
  vi.mocked(window.showWarningMessage).mockClear();
  expect(await verify(otherKey)).toBe(false);
  expect(window.showWarningMessage).not.toHaveBeenCalled();
  expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('has changed') }));
  expect(await readFile(file, 'utf8')).toBe(pinned);
});

test('binds trust to both host and port, independently of username', async () => {
  expect(await verify()).toBe(true);
  expect(await verify(key, 'REMOTE.EXAMPLE')).toBe(true);
  expect(await verify(otherKey, 'remote.example', 2222)).toBe(true);
  expect(await verify(otherKey, 'another.example')).toBe(true);
  expect(window.showWarningMessage).toHaveBeenCalledTimes(3);
});

test('coalesces concurrent first-use prompts and rejects a competing key', async () => {
  const results = await Promise.all([verify(), verify(), verify(otherKey)]);
  expect(results).toEqual([true, true, false]);
  expect(window.showWarningMessage).toHaveBeenCalledTimes(1);
  expect(onError).toHaveBeenCalledTimes(1);
});

test('rejects corrupted trust data instead of asking to replace it', async () => {
  expect(await verify()).toBe(true);
  await writeFile(await fingerprintFile(), 'invalid fingerprint');
  vi.mocked(window.showWarningMessage).mockClear();
  expect(await verify()).toBe(false);
  expect(window.showWarningMessage).not.toHaveBeenCalled();
  expect(onError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringContaining('Invalid') }));
});

test('rejects storage failures before prompting', async () => {
  await writeFile(join(storagePath, 'ssh-known-hosts'), 'not a directory');
  expect(await verify()).toBe(false);
  expect(window.showWarningMessage).not.toHaveBeenCalled();
  expect(onError).toHaveBeenCalled();
});

test('rejects a failure to persist an approved key', async () => {
  vi.mocked(window.showWarningMessage).mockImplementation(async () => {
    await writeFile(join(storagePath, 'ssh-known-hosts'), 'not a directory');
    return 'Trust host key';
  });
  expect(await verify()).toBe(false);
  expect(onError).toHaveBeenCalled();
});
