var { default: { uniqueID, password, peerURL, proxy, CA, chainID, domain, cnfstr } } = await import('../etc/config.json', { with: { type: 'json' } });
export { uniqueID, password, peerURL, proxy, CA, chainID, domain, cnfstr };
