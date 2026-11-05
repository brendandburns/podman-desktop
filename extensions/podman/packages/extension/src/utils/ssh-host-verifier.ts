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
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { window } from '@podman-desktop/api';

const pendingTrust = new Map<string, Promise<string | undefined>>();

function hasCode(error: unknown, code: string): boolean {
  return error instanceof Error && 'code' in error && error.code === code;
}

async function readFingerprint(file: string): Promise<string | undefined> {
  try {
    const fingerprint = (await readFile(file, 'utf8')).trim();
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) {
      throw new Error(`Invalid SSH host key fingerprint in ${file}.`);
    }
    return fingerprint;
  } catch (error) {
    if (hasCode(error, 'ENOENT')) {
      return undefined;
    }
    throw error;
  }
}

async function trustHostKey(
  directory: string,
  file: string,
  endpoint: string,
  fingerprint: string,
): Promise<string | undefined> {
  const trusted = await readFingerprint(file);
  if (trusted) {
    return trusted;
  }

  const approval = await window.showWarningMessage(
    `The SSH host key for ${endpoint} is unknown. SHA256 fingerprint: ${fingerprint}. ` +
      'Verify this fingerprint with the machine administrator through a trusted channel before trusting it.',
    'Trust host key',
    'Cancel',
  );
  if (approval !== 'Trust host key') {
    return undefined;
  }

  await mkdir(directory, { recursive: true, mode: 0o700 });
  try {
    // Exclusive creation prevents a simultaneous connection from replacing a trusted key.
    await writeFile(file, `${fingerprint}\n`, { flag: 'wx', mode: 0o600 });
    return fingerprint;
  } catch (error) {
    if (hasCode(error, 'EEXIST')) {
      return readFingerprint(file);
    }
    throw error;
  }
}

export function createSshHostVerifier(
  storagePath: string,
  host: string,
  port: number,
  onError: (error: Error) => void,
): (key: Buffer, callback: (valid: boolean) => void) => void {
  const endpoint = `[${host.replace(/^\[|\]$/g, '').toLowerCase()}]:${port}`;
  const directory = join(storagePath, 'ssh-known-hosts');
  const file = join(directory, createHash('sha256').update(endpoint).digest('hex'));

  return (key, callback): void => {
    const fingerprint = `SHA256:${createHash('sha256').update(key).digest('base64').replace(/=+$/, '')}`;
    let trust = pendingTrust.get(file);
    if (!trust) {
      trust = trustHostKey(directory, file, endpoint, fingerprint);
      pendingTrust.set(file, trust);
    }
    const pending = trust;
    void pending
      .then(trusted => {
        if (!trusted) {
          throw new Error(`SSH host key for ${endpoint} was not trusted. Connection refused.`);
        }
        if (trusted !== fingerprint) {
          throw new Error(
            `SSH host key for ${endpoint} has changed. Expected ${trusted}, received ${fingerprint}. ` +
              `Connection refused. Verify the change through a trusted channel before removing ${file}.`,
          );
        }
        callback(true);
      })
      .catch((error: unknown) => {
        const verificationError = error instanceof Error ? error : new Error(String(error));
        console.error('SSH host key verification failed:', verificationError);
        onError(verificationError);
        callback(false);
        void window.showErrorMessage(verificationError.message).catch((notificationError: unknown) => {
          console.error('Unable to display SSH host key verification error:', notificationError);
        });
      })
      .finally(() => {
        if (pendingTrust.get(file) === pending) {
          pendingTrust.delete(file);
        }
      });
  };
}
