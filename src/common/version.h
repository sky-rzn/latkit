/* SPDX-License-Identifier: GPL-2.0 */
/* Single source of the agent version string, used for --version, the --help
 * header, the startup banner and the OTLP resource (service.version) plus
 * instrumentation scope (Р31/Р45). LATKIT_VERSION is injected by CMake from
 * `git describe --tags --always --dirty` (overridable with -DLATKIT_VERSION=);
 * the fallback covers compilation outside the CMake build. */
#ifndef LATKIT_VERSION_H
#define LATKIT_VERSION_H

#ifndef LATKIT_VERSION
#define LATKIT_VERSION "unknown"
#endif

#define LK_VERSION LATKIT_VERSION

#endif /* LATKIT_VERSION_H */
