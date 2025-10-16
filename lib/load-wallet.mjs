async function loadWallet(filename, dir = 'wallets') {
    var { default: wallet } = await import('../' + dir + '/' + filename, { with: { type: 'json' } });
    return JSON.stringify(wallet);
}
var adminWalletJSON = await loadWallet('admin-wallet.json', 'etc');
export { loadWallet, adminWalletJSON };
