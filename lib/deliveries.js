/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';

const {config} = bedrock;

// FIXME: create storage API for pending deliveries
// FIXME: each pending delivery may include optionally encrypted VCs for
// ...pickup and / or VC templates and required VCs that must be provided
// ...to populate those templates
// ...if a template is provided, then the ability to issue the VC must also
// ...be provided; in version 1, this may be a reference to a zcap and the
// ...the zcap client to invoke it -- which presumes installation on some
// ...service with those capabilities as opposed to an external service config
