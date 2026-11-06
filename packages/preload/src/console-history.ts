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

import type { LogType } from '@desktop-framework/api';

export const MAX_CONSOLE_HISTORY_ENTRIES = 1_000;
export const MAX_CONSOLE_HISTORY_BYTES = 1024 * 1024;
export const MAX_CONSOLE_MESSAGE_BYTES = 16 * 1024;
const TRUNCATION_MARKER = ' [truncated]';
const CREDENTIAL_FIELDS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  '(?:access[-_]?|refresh[-_]?|auth[-_]?)?token',
  'api[-_]?key',
  'client[-_]?secret',
  'private[-_]?key',
].join('|');
const QUOTED_VALUE = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/;
const UNQUOTED_VALUE = /\[REDACTED\]|[^\s,;&}\]]+/;
const AUTHORIZATION = new RegExp(
  String.raw`(\bauthorization\b["']?\s*[:=]\s*)(${QUOTED_VALUE.source}|(?:Bearer|Basic)\s+[^\s,;}\]]+|${UNQUOTED_VALUE.source})`,
  'gi',
);
const CREDENTIAL_ASSIGNMENT = new RegExp(
  String.raw`(\b(?:${CREDENTIAL_FIELDS})\b["']?\s*[:=]\s*)(${QUOTED_VALUE.source}|${UNQUOTED_VALUE.source})`,
  'gi',
);
const CREDENTIAL_ARGUMENT = new RegExp(String.raw`(--(?:${CREDENTIAL_FIELDS})\s+)(${QUOTED_VALUE.source}|\S+)`, 'gi');

interface ConsoleLogEntry {
  logType: LogType;
  date: Date;
  message: string;
}

function redactMessage(message: string): string {
  return message
    .replace(
      /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z]+ )?PRIVATE KEY-----|$)/g,
      '[REDACTED]',
    )
    .replace(AUTHORIZATION, '$1[REDACTED]')
    .replace(/\b(Bearer|Basic)\s+[a-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
    .replace(/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/@'"]+@/gi, '$1[REDACTED]@')
    .replace(CREDENTIAL_ASSIGNMENT, '$1[REDACTED]')
    .replace(CREDENTIAL_ARGUMENT, '$1[REDACTED]');
}

function boundMessage(message: string): { message: string; bytes: number } {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { ignoreBOM: true });
  const encoded = encoder.encode(message.slice(0, MAX_CONSOLE_MESSAGE_BYTES + 1));
  if (encoded.byteLength <= MAX_CONSOLE_MESSAGE_BYTES) {
    // Decoding detaches retained text from potentially large source strings after redaction.
    return { message: decoder.decode(encoded), bytes: encoded.byteLength };
  }

  // Streaming decoding omits an incomplete trailing UTF-8 character.
  const truncated =
    decoder.decode(encoded.subarray(0, MAX_CONSOLE_MESSAGE_BYTES - TRUNCATION_MARKER.length), {
      stream: true,
    }) + TRUNCATION_MARKER;
  return { message: truncated, bytes: encoder.encode(truncated).byteLength };
}

export class ConsoleHistory {
  private readonly entries: { entry: ConsoleLogEntry; bytes: number }[] = [];
  private bytes = 0;

  append(logType: LogType, message: string): void {
    const bounded = boundMessage(redactMessage(message));
    this.entries.push({ entry: { logType, date: new Date(), message: bounded.message }, bytes: bounded.bytes });
    this.bytes += bounded.bytes;

    while (this.entries.length > MAX_CONSOLE_HISTORY_ENTRIES || this.bytes > MAX_CONSOLE_HISTORY_BYTES) {
      const removed = this.entries.shift();
      if (removed) {
        this.bytes -= removed.bytes;
      }
    }
  }

  getLogs(): ConsoleLogEntry[] {
    return this.entries.map(({ entry }) => ({ ...entry, date: new Date(entry.date) }));
  }

  clear(): void {
    this.entries.length = 0;
    this.bytes = 0;
  }
}
