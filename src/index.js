import 'bootstrap';
import 'bootstrap/dist/css/bootstrap.min.css';
//import "./style.css";
var _ = require('file-loader?name=[name].[ext]!./index.html');
import img from "./coinplus-icon.png";
import imglogo from "./coinplus-logo.png";
//const $ = require('jquery');
import $ from "jquery";
import {raise_if_bad_address, verify_solo_check, recompute_private_key, compute_address, compute_wif_privkey} from "./utils";
import {reconstruct_secrets} from "./shamir";


function get_secrets_solo(){
  var secret1_b58 = $("#secret1").val();
  var secret2_b58 = $("#secret2").val();
  if (secret1_b58.length == 30 && secret2_b58.length == 30)
  {
    if(verify_solo_check(secret1_b58, 1) === false){
      myalert("#errorrecompute", "<strong>Error.</strong> The secrets 1 checksum is not valid, please verify your secret 1");
      throw ("Secret Invalid");
    }
    if(verify_solo_check(secret2_b58, 1) === false){
      myalert("#errorrecompute", "<strong>Error.</strong> The secrets 2 checksum is not valid, please verify your secret 2");
      throw ("Secret Invalid");
    }
    secret1_b58 = secret1_b58.slice(0, -1);
    secret2_b58 = secret2_b58.slice(0, -1);
  }
  else if (secret1_b58.length == 28 && secret2_b58.length == 14)
  {
    //nothing to do
  }
  else{
    if (secret1_b58.length == 30){
      var err = "secret 2 should be of size 30";
    }
    else if (secret2_b58.length == 30){
      err = "secret 1 should be of size 30";
    }
    else if (secret1_b58.length == 28){
      err = "secret 1 is of size 28, therefore secret 2 should be of size 14";
    }
    else if (secret2_b58.length == 14){
      err = "secret 2 is of size 14, therefore secret 1 should be of size 28";
    }
    else {
      err = "secret 1 should be of size 28 or 30 and secret 2 should be 14 or 30";
    }
    myalert("#errorrecompute", "<strong>Error.</strong> The secrets size are wrong, " + err);
    throw ("Secret Invalid");
  }
  return {secret1_b58: secret1_b58, secret2_b58: secret2_b58};
  
}

function get_secrets_solo_pro(){
  var secrets1 = [];
  var secrets2 = [];
  var cards = [];
  var err = "";
  var secret_p = parseInt($("#secret_p").val());
  if (secret_p < 2 ){
    myalert("#errorrecompute", "<strong>Error.</strong> the number of required card should be at least 2");
    throw ("Not enough cards");
  }

  for (var card_form_number=1; card_form_number <= secret_p; card_form_number++){
    var card_number = parseInt($("#card_number_"+card_form_number).val());
    cards.push(card_number);
    var secret1_b58_temp = $("#secret1_"+card_form_number).val();
    var secret2_b58_temp = $("#secret2_"+card_form_number).val();
    var no_version = secrets1.length == 0;
    var no_version_or_version_1 = no_version || secrets1[0].length == 29;
    var no_version_or_version_2 = no_version || secrets1[0].length == 28;
    if (secret1_b58_temp.length == 30 && secret2_b58_temp.length == 30 && no_version_or_version_2)
    {
      if(verify_solo_check(secret1_b58_temp, 1) === false){
        myalert("#errorrecompute", "<strong>Error.</strong> The secrets 1 of the card "+card_number+" checksum is not valid, please verify your secret 1");
        throw ("Secret Invalid");
      }
      if(verify_solo_check(secret2_b58_temp, 1) === false){
        myalert("#errorrecompute", "<strong>Error.</strong> The secrets 2 of the card "+card_number+" checksum is not valid, please verify your secret 2");
        throw ("Secret Invalid");
      }
      secrets1.push(secret1_b58_temp.slice(0, -1));
      secrets2.push(secret2_b58_temp.slice(0, -1));
    }
    else if (secret1_b58_temp.length == 28 && secret2_b58_temp.length == 14  && no_version_or_version_1)
    {
      secrets1.push(secret1_b58_temp);
      secrets2.push(secret2_b58_temp);
    }
    else{
      if (no_version){
        if (secret1_b58_temp.length == 30){
          var err = "secret 2 of card "+ card_number +" should be of size 30";
        }
        else if (secret2_b58_temp.length == 30){
          err = "secret 1 of card "+ card_number +" should be of size 30";
        }
        else if (secret1_b58_temp.length == 28){
          err = "secret 2 of card "+ card_number +" should be of size 14";
        }
        else if (secret2_b58_temp.length == 14){
          err = "secret 1 of card "+ card_number +" should be of size 28";
        }
        else{
          err = "secret 1 of card "+ card_number +" should be of size 28 or 30 and secret 2 should be 14 or 30";
        }
      }
      else if (no_version_or_version_2){
        if(secret1_b58_temp.length !== 30){
          err = "secret 1 of card "+ card_number +" should be of size 30";
        }
        if(secret2_b58_temp.length !== 30){
          err = "secret 2 of card "+ card_number +" should be of size 30";
        }
      }
      else if (no_version_or_version_1){
        if(secret1_b58_temp.length !== 28){
          err = "secret 1 of card "+ card_number +" should be of size 28";
        }
        if(secret2_b58_temp.length !== 14){
          err = "secret 2 of card "+ card_number +" should be of size 14";
        }
      }
      myalert("#errorrecompute", "<strong>Error.</strong> The secrets size are wrong, " + err);
      throw ("Secret Invalid");
    }
  }
  return reconstruct_secrets(secrets1, secrets2, cards)
}

async function recompute() {
  cleanprivate();
  var secrets;
  if ($("#type_solo").val() === "SOLO"){
  secrets = get_secrets_solo();
  }
  if ($("#type_solo").val() === "PRO"){
      secrets = get_secrets_solo_pro();
  }

  var enc = new TextEncoder();
  var secret1_b58_buff = enc.encode(secrets.secret1_b58);
  var secret2_b58_buff = enc.encode(secrets.secret2_b58);

  var value = 0;

  raise_if_bad_address($("#address_solo").val(), $("#crypto_solo").val(), function(){
      myalert("#errorrecompute", "<strong>Error.</strong> This is not a valid Address");
  })
  var pair = await recompute_private_key(secret1_b58_buff, secret2_b58_buff,
                                         function(progress){
                                          $('#recomputeprogress').css('width', progress + '%').attr('aria-valuenow', progress);
                                         },
                                         function(error){
                                          myalert("#errorrecompute", "<strong>Error.</strong>" + error);
                                          throw("recompute error");
                                         });
  pair.getPublic(); // force to compute the public key
  var newaddr = compute_address(pair.pub,  $("#crypto_solo").val());
  var entered_address = $("#address_solo").val();

  if($("#crypto_solo").val() == "ETH")
  {
    entered_address = entered_address.toLowerCase();
  }
  if($("#crypto_solo").val() == "BCH")
  {
    if (!entered_address.startsWith("bitcoincash:"))
    {
      entered_address = "bitcoincash:" + entered_address;
      $("#address_solo").val(entered_address)
    }
  }
  if (newaddr !== entered_address){
    myalert("#errorrecompute", "<strong>Error.</strong> The recomputed address is different than the address you entered. Please verify your address and secrets");
    throw("wrong address");
  }

  $("#publickey").val(pair.pub.encode("hex", true));
  $("#privatekey").val(pair.priv.toString(16));
  if ($("#crypto_solo").val() == "BTC" || $("#crypto_solo").val() == "BCH" || $("#crypto_solo").val() == "LTC")
  {
    $("#privatekeywif").val(compute_wif_privkey(pair.priv, $("#crypto_solo").val()  ));
  }

  value = 100;
  $('#recomputeprogress').css('width', value + '%').attr('aria-valuenow', value);
}

function create_secret_form()
{
  if ($("#type_solo").val() === "SOLO"){
    $("#secrets_form")[0].innerHTML= `
        <div class="form-group">
            <label for="secret1">Secret 1:</label>
            <input type="text" class="form-control" id="secret1" onchange="remove_alerts(); cleanprivate(); " placeholder="Secret 1">
        </div>
        <div class="form-group">
            <label for="secret2">Secret 2:</label>
            <input type="text" class="form-control" id="secret2" onchange="remove_alerts(); cleanprivate();" placeholder="Secret 2">
        </div>`;
  }
  else{
    $("#secrets_form")[0].innerHTML= `
        <div class="form-group">
            <label for="secret_p">Number of SOLO Pro required to recompute the secrets:</label>
            <input type="text" class="form-control" id="secret_p" onchange="remove_alerts(); cleanprivate(); reformat_pro()" value="2">
            <label for="secret_n">out of:</label>
            <input type="text" class="form-control" id="secret_n" onchange="remove_alerts(); cleanprivate(); reformat_pro()" value="3">
        </div>
        <div class="form-group" id="secrets_form_pro">
        </div>`;
    reformat_pro();
    
  }
}
function reformat_pro(){
  $("#secrets_form_pro")[0].innerHTML = "";
  var secret_p = parseInt($("#secret_p").val());
  for (var card_form_number=1; card_form_number <= secret_p; card_form_number ++){
    $("#secrets_form_pro")[0].innerHTML += `
      <div class="form-group">
        <label for="card_number_${card_form_number}">Card number:</label>
        <input type="text" class="form-control" id="card_number_${card_form_number}" onchange="remove_alerts(); cleanprivate()" value="${card_form_number}"  placeholder="1">
      </div>
      <div class="form-group">
        <label for="secret1_${card_form_number}">Secret 1:</label>
        <input type="text" class="form-control" id="secret1_${card_form_number}" onchange="remove_alerts(); cleanprivate()" placeholder="Secret 1">
      </div>
      <div class="form-group">
        <label for="secret2_${card_form_number}">Secret 2:</label>
        <input type="text" class="form-control" id="secret2_${card_form_number}" onchange="remove_alerts(); cleanprivate()" placeholder="Secret 2">
      </div>`;
  }
}

function myalert(id, html) {
  var el = $(id)[0];
  el.innerHTML = html;
  el.style.display = 'block';
  el.scrollIntoView(true);
}

function cleanprivate() {
  $("#publickey").val("");
  $("#privatekey").val("");
  $("#privatekeywif").val("");
  if ($("#crypto_solo").val() == "BTC" || $("#crypto_solo").val() == "BCH" || $("#crypto_solo").val() == "LTC")
  {
    $("#privatekeywif_div").show();
  }
  else{
    $("#privatekeywif_div").hide();
  }
}

function remove_alerts() {
  $("#errorphishing")[0].style.display = 'none';
  $("#errorrecompute")[0].style.display = 'none';
}

window.remove_alerts = remove_alerts;
window.recompute = recompute;
window.cleanprivate = cleanprivate;
window.create_secret_form = create_secret_form;
window.reformat_pro = reformat_pro;

create_secret_form();

if (!window.location.href.startsWith("file:/")){
  myalert("#errorphishing", "<strong>Warning.</strong>. To avoid phishing attacks please run this website locally.");
}


