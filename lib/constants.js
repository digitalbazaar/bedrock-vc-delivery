/*!
 * Copyright (c) 2024-2026 Digital Bazaar, Inc.
 */
// allow up to 3 days to resolve invalid exchange issues (which also more than
// covers large exchange `variables` download and decoding times, etc.)
// (86400 seconds in 24 hours)
export const EXCHANGE_EXPIRY_GRACE_PERIOD = 86400 * 3 * 1000;
// TTL is measured in minutes, default is 15 minutes
export const EXCHANGE_TTL_DEFAULT = 60 * 15;
// 48 hours
export const EXCHANGE_TTL_MAX_IN_MS = 1000 * 60 * 60 * 24 * 2;

// maximum # of issuer instances that can be associated with a workflow
export const MAX_ISSUER_INSTANCES = 10;
// maximum # of OID4VP client profiles that can be associated with a workflow
export const MAX_OID4VP_CLIENT_PROFILES = 10;
