/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

// FIXME: create storage API for exchanges; each has a TTL; that TTL is short
// ...prior to the exchange getting used, but once used, the exchange record
// ...is marked as used and the TTL is extended to some other specified period
// ...of time; if any attempt is made to use the exchange again after it has
// ...been used then an auto-revocation or notification (as specified in the
// ...exchange record) is executed
// FIXME: each pending exchange may include optionally encrypted VCs for
// ...pickup and / or VC templates and required VCs that must be provided
// ...to populate those templates
// ...if any templates are provided, then the ability to issue the VC must also
// ...be provided; in version 1, this may be a reference to a zcap and the
// ...the zcap client to invoke it -- which presumes installation on some
// ...service with those capabilities as opposed to an external service config
