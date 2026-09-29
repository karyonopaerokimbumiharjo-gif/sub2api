// Match gateway.max_body_size (256 MiB by default). The private envelope adds
// credentials/session metadata and the SDK adds its own small default fields.
// Share this bound so a long tool/image history cannot fail at the next layer.
const gatewayMaxBodyBytes=Number(process.env.GATEWAY_MAX_BODY_SIZE||256*1024*1024);
if(!Number.isSafeInteger(gatewayMaxBodyBytes)||gatewayMaxBodyBytes<=0)throw Error('invalid_pi_body_limit');
export const maxRuntimeRequestBodyBytes=gatewayMaxBodyBytes+1024*1024;
export const maxControlRequestBodyBytes=8*1024*1024;
