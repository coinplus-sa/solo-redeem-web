const {raise_if_bad_address, verify_solo_check, recompute_private_key, compute_address, base58decode, base58encode, compute_wif_privkey} = require("./utils")
const {reconstruct_secrets} = require("./shamir")

var enc = new TextEncoder();

async function test(){

	console.log(raise_if_bad_address("1KVRp8a88ZtvUHJPtGuXM4iE3Xax5Uy2yx", "BTC", function(){console.log("error")}))
	try{
	console.log(raise_if_bad_address("1KVRp8a88ZtvUHJPtGuXM4iE3Xax5Uy2yx", "LTC", function(){console.log("assert error")}))
	throw("fail, should raise before")
	}
	catch{
	}
	console.log("verify_solo_check should be true:", verify_solo_check("T9dnCu7G2CbA9TUuVKWqvv6DDTFRd5",1))
	console.log("verify_solo_check should be false:", verify_solo_check("T9dnCu7G2CbA9TUuVKWqvv6DDTFRd6",1))
	console.log("verify_solo_check should be true:", verify_solo_check("TVJtBrNFwX4F8RDFhN9L7x6TNBYRzQ",1))

	//var secret1_b58="T9dnCu7G2CbA9TUuVKWqvv6DDTFRd5";
	//var secret2_b58="Y2czc3WMmZbutDiEaBKZ7G446ryYQG";
	var secret1_b58="KKgdj3GPqHC1SvhfnwWh3QGTDcmjNC";
	var secret2_b58="8pNJCQGQJgBo7tGzR9K43c7iZMBEi2";


	var secret1_b58_buff = enc.encode(secret1_b58.slice(0, -1));
	var secret2_b58_buff = enc.encode(secret2_b58.slice(0, -1));


    res = await recompute_private_key(secret1_b58_buff, secret2_b58_buff, function(){},function(){})
    res.getPublic();
    console.log("BTC")
    console.log(compute_address(res.pub, "BTC"))
    console.log("115KC7azrJ2s9D3V1oRjNtsi3yyvauXTEG")
    console.log("LTC")
    console.log(compute_address(res.pub, "LTC"))
    console.log("LKJGTKtpvxGvQ1jeBwR2euwUGCMCizobqX")
    console.log("XRP")
    console.log(compute_address(res.pub, "XRP"))
    console.log("rrnKUf2ziJp19DsVroRj4t15syyv2uXTNG")
    console.log("BCH")
    console.log(compute_address(res.pub, "BCH"))
    console.log("bitcoincash:qqqdpkt57ej58zek5srvcfq6khcxsfzp3vwsdadn98")
    console.log("XTZ")
    console.log(compute_address(res.pub, "XTZ"))
    console.log("tz2ELo7uRJ9Hc3fhMw6v6ouHrE4Ptm3hVyeb")
    console.log("ETH")
    console.log(compute_address(res.pub, "ETH"))
    console.log("0x10d998373Bf49A3AC5f0BFB1C991D3531Bd606d6")


    console.log("BTC")
    console.log(raise_if_bad_address("115KC7azrJ2s9D3V1oRjNtsi3yyvauXTEG"))
    console.log("115KC7azrJ2s9D3V1oRjNtsi3yyvauXTEG")
    console.log("LTC")
    console.log(raise_if_bad_address("LKJGTKtpvxGvQ1jeBwR2euwUGCMCizobqX","LTC", function(e){console.log(e)}))
    console.log("LKJGTKtpvxGvQ1jeBwR2euwUGCMCizobqX")
    console.log("XRP")
    console.log(raise_if_bad_address("rrnKUf2ziJp19DsVroRj4t15syyv2uXTNG","XRP", function(e){console.log(e)}))
    console.log("rrnKUf2ziJp19DsVroRj4t15syyv2uXTNG")
    console.log("ETH")
    console.log(raise_if_bad_address("0x10d998373Bf49A3AC5f0BFB1C991D3531Bd606d6","ETH", function(e){console.log(e)}))
    console.log("0x10d998373Bf49A3AC5f0BFB1C991D3531Bd606d6")
    console.log("XTZ")
    console.log(raise_if_bad_address("tz2ELo7uRJ9Hc3fhMw6v6ouHrE4Ptm3hVyeb","XTZ", function(e){console.log(e)}))
    console.log("tz2ELo7uRJ9Hc3fhMw6v6ouHrE4Ptm3hVyeb")
    console.log("BCH")
    console.log(raise_if_bad_address("bitcoincash:qqqdpkt57ej58zek5srvcfq6khcxsfzp3vwsdadn98","BCH", function(e){console.log(e)}))
    console.log("bitcoincash:qqqdpkt57ej58zek5srvcfq6khcxsfzp3vwsdadn98")

    return res


}



function test2(){
	s1 = ["tdkaqWo2zkMgZC1FL9udJcW3pu2f", "bzjYqKZ5dPYLEBHA8suWQwT8TcXt", "EZFUQQWKaX6BZe4VRwbCuVKTo6mn", "nKJMYmekr91EZaMFDLxinG73qMpk", "FGtCGQzPSFHVDz9RV6243FotaPXz", "dRzzZLXDLqvwYsT2FAmCgURz2C4J"]
	s2 = ["KqKPnPF5meCSLh","BTNVwHcL8XhNWd", "GBerGrGxLt8pUe", "a2ASo5ExQhWnEk", "6xuHVxWLKyqFmL", "s1sNPW566j6F7c"]
	cs = [1,2,3,4,5,6]
	expected = {secret1_b58:"6UJaQzEBgbYEYgEm1mbZaWUDtxBi",secret2_b58: "hKVXp9BDGDe1xr"}
	
	secrets1 = s1.slice(2,5)
	secrets2 = s2.slice(2,5)
	cards = cs.slice(2,5)
	res = reconstruct_secrets(secrets1, secrets2, cards)
	console.log("expected:",expected)
	console.log("resultat:",res)

	s1 = ["PCSFbT92Sx5hELPDuB6gH8Kk4ZvkcJ", "z1ejpRvAvL9KmreLJvjkCGXkersftx", "apsE3QhKPiCxKNuSigNp7QjmF9pYKY"]
	s2 = ["F1T2B4xB96EM7eKVmTXtTe57c4B6am", "HrgJAvH5Us8h3zarJsgh5rfNenyg9L", "LhuaAmbype32zLrCrHqVi5FdhXnFib"]
	s1 = ["PCSFbT92Sx5hELPDuB6gH8Kk4Zvkc", "z1ejpRvAvL9KmreLJvjkCGXkersft", "apsE3QhKPiCxKNuSigNp7QjmF9pYK"]
	s2 = ["F1T2B4xB96EM7eKVmTXtTe57c4B6a", "HrgJAvH5Us8h3zarJsgh5rfNenyg9", "LhuaAmbype32zLrCrHqVi5FdhXnFi"]
	cs = [1,2,3]
	expected = {secret1_b58:"nPDmNUMsya24gp87VRTcMz7jUGytBa",secret2_b58: "CADkBDdGoKL1BJ49E3P5qRUrZKNX15"}
	
	secrets1 = s1.slice(1,3)
	secrets2 = s2.slice(1,3)
	cards = cs.slice(1,3)
	res = reconstruct_secrets(secrets1, secrets2, cards)
	console.log("expected:",expected)
	console.log("resultat:",res)


}


test2()
test()

