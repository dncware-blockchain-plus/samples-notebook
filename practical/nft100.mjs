export default function nft100(func, args) {

    'use strict';
    var NFT_NAME = 'simple NFT implementation #100';
    var NFT_SYMBOL = 'NFT100';
    var TOTAL_SUPPLY = 100;
    var INITIAL_OWNER = 'u00000000';
    var BASE_URI = 'https://anywhere.com/';

    var caller = getCallerId();

    if (caller === 'anonymous') {
        throw 'It cannot be accessed anonymously.';
    }

    if (!keyValueGet('initialized')) {
        keyValueSet('initialized', true);
        keyValueSet(['balance', INITIAL_OWNER], TOTAL_SUPPLY);
        for (var i = 0; i < TOTAL_SUPPLY; i++) {
            var tokenId = 'token' + i;
            keyValueSet(['ownedTokens', INITIAL_OWNER, i], tokenId);
            keyValueSet(['ownedTokenIndex', tokenId], i);
            keyValueSet(['owner', tokenId], INITIAL_OWNER);
        }
    }

    switch (func) {
        case 'name':
            return NFT_NAME;

        case 'symbol':
            return NFT_SYMBOL;

        case 'totalSupply':
            return TOTAL_SUPPLY;

        case 'balanceOf':
            var owner = args.owner;
            requireContractOrUser(owner, 'invalid args.owner');
            var quantity = keyValueGet(['balance', owner]) || 0;
            return quantity;

        case 'ownerOf':
            var tokenId = args.tokenId;
            var owner = requireValidTokenId(tokenId, 'invalid args.tokenId');
            return owner;

        case 'tokenURI':
            var tokenId = args.tokenId;
            requireValidTokenId(tokenId, 'invalid args.tokenId');
            return BASE_URI + tokenId;

        case 'tokenOfOwnerByIndex':
            var owner = args.owner;
            var index = args.index;
            requireContractOrUser(owner, 'invalid args.owner');
            requireInteger(index, 'invalid args.index');
            var tokenId = keyValueGet(['ownedTokens', owner, index]);
            requireValidTokenId(tokenId, 'owner index out of bounds');
            return tokenId;

        case 'tokenByIndex':
            var index = args.index;
            var tokenId = 'token' + index;
            requireValidTokenId(tokenId, 'invalid args.index');
            return tokenId;

        case 'approve':
            // approvedにnullまたはundefinedを設定した場合は、approveの解除になります。
            var approved = args.approved;
            var tokenId = args.tokenId;
            if (approved != null) requireContractOrUser(approved, 'invalid args.approved');
            var owner = requireValidTokenId(tokenId, 'invalid args.tokenId');
            if (caller !== owner) {
                var operated = !!keyValueGet(['operated', owner, caller]);
                require(operated, 'caller not authorized for ' + tokenId);
            }
            if (approved == null) {
                keyValueDelete(['tokenApproval', tokenId]);
            } else {
                keyValueSet(['tokenApproval', tokenId], approved);
            }
            return;

        case 'getApproved':
            var tokenId = args.tokenId;
            requireValidTokenId(tokenId, 'invalid args.tokenId');
            var approved = keyValueGet(['tokenApproval', tokenId]) || null;
            return approved;

        case 'setApprovalForAll':
            var operator = args.operator;
            var approved = args.approved;
            requireContractOrUser(operator, 'invalid args.operator');
            require(typeof approved === 'boolean', 'invalid args.approved');
            if (approved) {
                keyValueSet(['operated', caller, operator], true);
            } else {
                keyValueDelete(['operated', caller, operator]);
            }
            return;

        case 'isApprovedForAll':
            var owner = args.owner;
            var operator = args.operator;
            requireContractOrUser(owner, 'invalid args.owner');
            requireContractOrUser(operator, 'invalid args.operator');
            var approved = !!keyValueGet(['operated', owner, operator]);
            return approved;

        case 'transferFrom':
        case 'safeTransferFrom':
            var from = args.from;
            var to = args.to;
            var tokenId = args.tokenId;
            requireContractOrUser(from, 'invalid args.from');
            requireContractOrUser(to, 'invalid args.to');
            var owner = requireValidTokenId(tokenId, 'invalid args.tokenId');
            require(owner === from, 'unexpected args.from');
            if (caller !== owner) {
                var operated = !!keyValueGet(['operated', owner, caller]);
                var approval = keyValueGet(['tokenApproval', tokenId]);
                require(operated || caller === approval, 'caller not authorized for ' + tokenId);
            }
            _tokenTransfer(from, to, tokenId);
            discloseTo(from, to);
            if (func === 'safeTransferFrom') {
                require(checkOnNFTReceived(from, to, tokenId, args.data), 'unexpected receiver');
            }
            return;

        default:
            throw 'invalid func';
    }

    function _tokenTransfer(from, to, tokenId) {
        if (from === to) return;
        var max = keyValueGet(['balance', from]) - 1;
        assert(max >= 0);
        if (max === 0) {
            keyValueDelete(['balance', from]);
        } else {
            keyValueSet(['balance', from], max);
        }
        var idx = keyValueGet(['ownedTokenIndex', tokenId]);
        if (idx !== max) {
            var tid = keyValueGet(['ownedTokens', from, max]);
            keyValueSet(['ownedTokens', from, idx], tid);
            keyValueSet(['ownedTokenIndex', tid], idx);
        }
        keyValueDelete(['ownedTokens', from, max]);
        var length = keyValueGet(['balance', to]) || 0;
        keyValueSet(['balance', to], length + 1);
        keyValueSet(['ownedTokens', to, length], tokenId);
        keyValueSet(['ownedTokenIndex', tokenId], length);
        keyValueSet(['owner', tokenId], to);
        keyValueDelete(['tokenApproval', tokenId]);
    }

    function checkOnNFTReceived(from, to, tokenId, data) {
        if (!isContract(to)) return true;
        return 'd56Kq6n1' === openContract(to).call({
            func: 'onNFTReceived',
            args: {
                operator: caller,
                from: from,
                tokenId: tokenId,
                data: data
            }
        });
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

    function requireValidTokenId(id, message) {
        require(typeof id === 'string', message);
        var owner = keyValueGet(['owner', id]);
        require(owner != null, message);
        return owner;
    }

    function requireInteger(i, message) {
        require(typeof i === 'number' && isFinite(i) && Math.floor(i) === i, message);
    }

    function assert(condition, message) {
        if (!condition) abortTransaction('ASSERT:' + (message || ''));
    }

}
