export default function coin100(func, args) {

    'use strict';
    var COIN_NAME = 'simple COIN implementation #100';
    var COIN_SYMBOL = 'Coin100';
    var TOTAL_SUPPLY = 100000000;
    var DECIMALS = 0;
    var INITIAL_OWNER = 'u00000000';

    var caller = getCallerId();
    requireContractOrUser(caller, 'invalid caller');

    if (!keyValueGet('initialized')) {
        keyValueSet('initialized', true);
        keyValueSet(['balance', INITIAL_OWNER], TOTAL_SUPPLY);
    }

    switch (func) {
        case 'name':
            return COIN_NAME;

        case 'symbol':
            return COIN_SYMBOL;

        case 'decimals':
            return DECIMALS;

        case 'totalSupply':
            return TOTAL_SUPPLY;

        case 'balanceOf':
            var owner = args.owner;
            requireContractOrUser(owner, 'invalid args.owner');
            var balance = keyValueGet(['balance', owner]) || 0;
            return balance;

        case 'transfer':
            var to = args.to;
            var value = args.value;
            requireContractOrUser(to, 'invalid args.to');
            requireNonNegativeSafeInteger(value, 'invalid args.value');
            var balance = keyValueGet(['balance', caller]) || 0;
            require(balance >= value, 'insufficient balance');
            keyValueSet0(['balance', caller], balance - value);
            keyValueAdd(['balance', to], value);
            discloseTo(to);
            return true;

        case 'transferFrom':
            var from = args.from;
            var to = args.to;
            var value = args.value;
            requireContractOrUser(from, 'invalid args.from');
            requireContractOrUser(to, 'invalid args.to');
            requireNonNegativeSafeInteger(value, 'invalid args.value');
            var allowance = keyValueGet(['allowed', from, caller]) || 0;
            var balance = keyValueGet(['balance', from]) || 0;
            require(allowance >= value, 'insufficient allowance');
            require(balance >= value, 'insufficient balance');
            keyValueSet0(['allowed', from, caller], allowance - value);
            keyValueSet0(['balance', from], balance - value);
            keyValueAdd(['balance', to], value);
            discloseTo(from, to);
            return true;

        case 'approve':
            var spender = args.spender;
            var value = args.value;
            var old = args.old;
            requireContractOrUser(spender, 'invalid args.spender');
            requireNonNegativeSafeInteger(value, 'invalid args.value');
            if (old != null) {
                requireNonNegativeSafeInteger(old, 'invalid args.old');
                var allowance = keyValueGet(['allowed', owner, spender]) || 0;
                require(old === allowance, 'old value mismatch');
            }
            keyValueSet0(['allowed', caller, spender], value);
            return true;

        case 'allowance':
            var owner = args.owner;
            var spender = args.spender;
            requireContractOrUser(owner, 'invalid args.owner');
            requireContractOrUser(spender, 'invalid args.spender');
            var allowance = keyValueGet(['allowed', owner, spender]) || 0;
            return allowance;

        default:
            throw 'invalid func';
    }

    function keyValueSet0(key, value) {
        if (value === 0) {
            keyValueDelete(key);
        } else {
            keyValueSet(key, value);
        }
    }

    function isUser(id) {
        return typeof id === 'string' && /^u\d{4,19}$/.test(id);
    }

    function isContract(id) {
        return typeof id === 'string' && /^c0\d{3,18}$/.test(id);
    }

    function require(condition, message) {
        if (!condition) throw message;
    }

    function requireContractOrUser(id, message) {
        require(isUser(id) || isContract(id), message);
    }

    function requireNonNegativeSafeInteger(i, message) {
        require(typeof i === 'number' && isFinite(i) && Math.floor(i) === i && 0 <= i && i < 9e15, message);
    }

}
