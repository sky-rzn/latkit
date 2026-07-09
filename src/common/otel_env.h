/* SPDX-License-Identifier: GPL-2.0 */
/* Environment-layer helpers (Р34, STAGE5.md task 5.2). The config priority is
 * flag > env > default; standard OpenTelemetry variables are honoured as the
 * defaults for their flags so an agent deployed beside other OTel tooling picks
 * up the ambient configuration (OTEL_EXPORTER_OTLP_ENDPOINT, ..._HEADERS,
 * OTEL_RESOURCE_ATTRIBUTES, OTEL_SERVICE_NAME). This file provides the small
 * mechanics used by task 5.2; the full LATKIT_* table over every flag lands in
 * task 5.4. No YAML in v1 (Р34). */
#ifndef LATKIT_OTEL_ENV_H
#define LATKIT_OTEL_ENV_H

/* Split a comma-separated "k=v,k2=v2" string (the OTEL_*_HEADERS /
 * OTEL_RESOURCE_ATTRIBUTES format) into a freshly allocated array of "k=v"
 * strings, trimming surrounding whitespace and dropping entries without a '='.
 * *n receives the count; returns NULL (and *n = 0) when nothing usable is found.
 * Free with lk_free_pairs. */
char **lk_split_pairs(const char *s, int *n);
void lk_free_pairs(char **arr, int n);

#endif /* LATKIT_OTEL_ENV_H */
