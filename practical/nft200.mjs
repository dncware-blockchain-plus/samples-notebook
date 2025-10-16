export default function nft100(func, args) {

    'use strict';
    var NFT_NAME = 'mintable NFT implementation';
    var NFT_SYMBOL = 'NFTM';
    var ADMIN_USER = 'u00000000'; // can mint/burn
    var LOG_CONTRACT = 'NFTLOG';

    var caller = getCallerId();

    if (caller === 'anonymous') {
        throw 'It cannot be accessed anonymously.';
    }

    if (!keyValueGet('nextTokenId')) {
        keyValueSet('totalSupply', 0);
        keyValueSet('nextTokenId', 1);
    }

    switch (func) {
        case 'name':
            return NFT_NAME;

        case 'symbol':
            return NFT_SYMBOL;

        case 'totalSupply':
            return keyValueGet('totalSupply');

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
            return keyValueGet(['tokenURI', tokenId]);

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
            requireInteger(index, 'invalid args.index');
            var tokenId = keyValueGet(['tokens', index]);
            requireValidTokenId(tokenId, 'index out of bounds');
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
            if (from !== to) {
                _tokenDetach(from, tokenId);
                _tokenAttach(to, tokenId);
                log(from, to, tokenId);
            }
            discloseTo(from, to);
            if (func === 'safeTransferFrom') {
                require(checkOnNFTReceived(from, to, tokenId, args.data), 'unexpected receiver');
            }
            return;

        case 'mint':
            var to = args.to;
            var uri = args.uri;
            requireContractOrUser(to, 'invalid args.to');
            require(typeof uri === 'string', 'invalid args.uri');
            require(caller === ADMIN_USER, 'caller is not ADMIN');
            var next = keyValueGet('nextTokenId');
            keyValueSet('nextTokenId', next + 1);
            var tokenId = String(next);
            _tokenAdd(tokenId, uri);
            _tokenAttach(to, tokenId);
            log('', to, tokenId);
            return tokenId;

        case 'burn':
            var tokenId = args.tokenId;
            var owner = requireValidTokenId(tokenId, 'invalid args.tokenId');
            require(caller === ADMIN_USER || caller == owner, 'caller is not ADMIN nor owner');
            _tokenDetach(owner, tokenId);
            _tokenDel(tokenId);
            log(owner, '', tokenId);
            return;

        default:
            throw 'invalid func';
    }

    function _tokenAdd(tokenId, tokenURI) {
        var length = keyValueGet('totalSupply') || 0;
        keyValueSet('totalSupply', length + 1);
        keyValueSet(['tokens', length], tokenId);
        keyValueSet(['tokenIndex', tokenId], length);
        keyValueSet(['tokenURI', tokenId], tokenURI);
    }

    function _tokenDel(tokenId) {
        var max = keyValueGet('totalSupply') - 1;
        keyValueSet('totalSupply', max);
        var idx = keyValueGet(['tokenIndex', tokenId]);
        if (idx !== max) {
            var tid = keyValueGet(['tokens', max]);
            keyValueSet(['tokens', idx], tid);
            keyValueSet(['tokenIndex', tid], idx);
        }
        keyValueDelete(['tokens', max]);
        keyValueDelete(['tokenIndex', tokenId]);
        keyValueDelete(['ownedTokenIndex', tokenId]);
        keyValueDelete(['owner', tokenId]);
        keyValueDelete(['tokenURI', tokenId]);
    }

    function _tokenAttach(owner, tokenId) {
        var length = keyValueGet(['balance', owner]) || 0;
        keyValueSet(['balance', owner], length + 1);
        keyValueSet(['ownedTokens', owner, length], tokenId);
        keyValueSet(['ownedTokenIndex', tokenId], length);
        keyValueSet(['owner', tokenId], owner);
    }

    function _tokenDetach(owner, tokenId) {
        var max = keyValueGet(['balance', owner]) - 1;
        assert(max >= 0);
        if (max === 0) {
            keyValueDelete(['balance', owner]);
        } else {
            keyValueSet(['balance', owner], max);
        }
        var idx = keyValueGet(['ownedTokenIndex', tokenId]);
        if (idx !== max) {
            var tid = keyValueGet(['ownedTokens', owner, max]);
            keyValueSet(['ownedTokens', owner, idx], tid);
            keyValueSet(['ownedTokenIndex', tid], idx);
        }
        keyValueDelete(['ownedTokens', owner, max]);
        keyValueDelete(['tokenApproval', tokenId]);
    }

    function log(from, to, tokenId) {
        openContract(LOG_CONTRACT).call({ from: from, to: to, tokenId: tokenId });
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
