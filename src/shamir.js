//const {base58decode, base58encode} = import ("./utils.js");
import {base58decode, base58encode} from "./utils";
import BN from "bn.js";

function reconstruct_secrets(secrets1, secrets2, cards){
	var secret1_shares = []
	var secret2_shares = []
	var secret1_length = secrets1[0].length;
	var secret2_length = secrets2[0].length;
	console.log(secrets1,secrets2)
	for (var i = 0 ; i < cards.length; i++){
		secret1_shares.push({x:new BN(cards[i]),y:base58decode(secrets1[i])})
		secret2_shares.push({x:new BN(cards[i]),y:base58decode(secrets2[i])})
	}
	var secret1_b58 = reconstruct_from_share(secret1_shares, secret1_length)
	var secret2_b58 = reconstruct_from_share(secret2_shares, secret2_length)
	console.log(secret1_b58,secret2_b58)
	return {secret1_b58:secret1_b58, secret2_b58: secret2_b58}
}

function lagrange(shares, modulus){
	console.log(shares)
    var s = new BN(0)
    for (var pi in shares){
        var factors = new BN(1);
        for (var pj in shares){
            if (pi != pj){
                var nom = (new BN(0)).sub(shares[pj].x);
                var den = shares[pi].x.sub(shares[pj].x);
                var oneoverden = den.egcd(modulus).a
                factors = factors.mul(nom).mul(oneoverden);
            }
        }
        s = s.add(shares[pi].y.mul(factors))
    }
    return s.umod(modulus)

}

function reconstruct_from_share(shares, l){
	var modulus = null;
    if(l == 14)
        modulus = new BN("4875194084160298409672797",10)
    if(l == 28)
        modulus = new BN("23767517358231570773047645414309870043308402671871",10)
    if(l == 29)
        modulus = new BN("1378516006777431104836763434029972462511887354953893",10)
    var secret_int = lagrange(shares, modulus)
    console.log(secret_int.toString(10));
    var b58secret = base58encode(secret_int)
    return "1".repeat(l-b58secret.length)+b58secret
}

export { reconstruct_secrets };


